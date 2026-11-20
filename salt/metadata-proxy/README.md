metadata-proxy
==============

Gives each configured local user its own Google service account, instead of
the VM's. The proxy listens on one loopback port per user, iptables redirects
that user's traffic to `169.254.169.254:80` there, and the proxy answers with
tokens for that user's account only, minted through the IAM Credentials API
with the VM's identity. Everyone else but root and the proxy itself is
rejected from the metadata server, so a process on the host gets exactly the
identity it was given, or none.

The redirect only decides where a user's own traffic lands, so each identity
port is guarded twice against other users connecting to it directly: an
iptables rule rejects connections to the port from any other uid, and the
proxy looks up the uid that owns the client end of every connection in
`/proc/net/tcp` and `/proc/net/tcp6` and refuses anyone but the port's user.
The second check means a wrong rule, or a port that moved to another user,
fails closed. The ports are privileged (900 and up by default) and the
service holds `CAP_NET_BIND_SERVICE`, so no other local user can bind one
while the proxy is down and answer the redirected requests itself.

Ports are assigned from `base_port` in a fixed order, identities first and
then the default compute SA users, each sorted by name. Adding a user can
therefore move the ports of the ones after it. The proxy restarts with the new
mapping before the firewall rules are rebuilt at the end of the run, so until
then a user whose port moved is refused, not given another user's identity.

Application default credentials work unchanged for the mapped users: the
Google provider for Terraform, gcloud, google-auth, the Cloud SDKs and
`apt-transport-artifact-registry` all read the metadata server and refresh
their own tokens.

The proxy serves what application default credentials need and nothing else:
the service account's token, email, scopes and identity (ID token), the
service account listing, `project/project-id`, `project/numeric-project-id`,
`instance/zone` and `instance/name`. Instance and project attributes are never
passed through.

The mapped users must exist on the host when the firewall rules are applied,
since iptables resolves them to uids when loading the ruleset.


Prerequisites
-------------

The VM's service account needs `roles/iam.serviceAccountTokenCreator` on every
service account in `identities`, and on the project's default compute service
account if `default_compute_sa_users` is set. Terraform owns those grants.

Access through the proxy shows up in the audit logs as the mapped service
account, with the VM's account in the delegation info.


Pillar
------

```yaml
metadata-proxy:
    identities:
        # local user -> service account the proxy hands out tokens for
        terraform: terraform@my-project.iam.gserviceaccount.com
    # Local users that get the project's default compute service account.
    # apt runs its fetch methods as _apt, so any host that installs packages
    # from Artifact Registry needs it here.
    default_compute_sa_users:
        - _apt
    # Optional, the first of the loopback ports the proxy listens on. Every
    # allocated port must stay below 1024, which the pillar check enforces.
    base_port: 900
```

When this pillar is set, `iptables.cloud_metadata` allows root to the metadata
server (ports 80 and 443, the latter being its mTLS endpoint) and rejects
every other user, instead of allowing everyone, so a host that has the pillar
but has not applied this state keeps root's access and nobody else's, whatever
other port 80 or 443 rules it carries. Both rules come before the allow for
established connections, so a connection opened before the rules landed is
cut off too. This state adds the proxy's own access between the two, the
redirects, and the identity port rules.

To take the proxy off a host again, drop the pillar and the state, reapply,
then stop and disable the service and remove its unit, config, script and
user by hand, as nothing manages their absence. The firewall state only writes
the nat table when something uses it, so the redirects stay loaded until
`iptables -t nat -F OUTPUT` is run once as well; until then the mapped users
reach a port nothing listens on.


Testing
-------

    $ python3 -m pytest salt/metadata-proxy

The HTTP-level test needs loopback connections and skips where it cannot
make one.
