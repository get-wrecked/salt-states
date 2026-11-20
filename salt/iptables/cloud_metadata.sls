{% if salt['pillar.get']('metadata-proxy') %}
# A host running metadata-proxy decides per user who reaches the metadata
# server: root here, the proxy's own user in its state, and nobody else. The
# reject lives here rather than in the proxy state so that a host with the
# pillar but without the state applied denies everyone but root, whatever
# other port 80 rules it has (unattended-upgrades opens it for _apt). Port
# 443 is the server's mTLS endpoint, which serves the same paths; the guest
# agent keeps the client certificate root-only, but the rules do not rely on
# that.
#
# Both rules are ordered ahead of the established-connections allow, so that
# a connection a user opened before the rules landed is cut off too, and the
# reject matches owned packets only, from any uid the kernel can hand out
# (subordinate uids go well past 65535): the kernel sends FIN and RST for
# closed sockets with no owner, and those must still pass. The proxy state
# puts its own user's allow between the two with require_in.
{% for family, address in (('ipv4', '169.254.169.254'), ('ipv6', 'fd20:ce::254')) %}
iptables-cloud-metadata-firewall-tcp-root-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: tcp
        - dports: 80,443
        - destination: {{ address }}
        - match:
            - comment
            - owner
        - comment: 'iptables.cloud_metadata: Allow root http to metadata service'
        - uid-owner: root
        - jump: ACCEPT
        - order: 1


iptables-cloud-metadata-firewall-tcp-reject-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: tcp
        - dports: 80,443
        - destination: {{ address }}
        - match:
            - comment
            - owner
        - comment: 'iptables.cloud_metadata: Reject everyone else from the metadata service'
        - uid-owner: 0-4294967294
        - jump: REJECT
        - reject-with: tcp-reset
        - order: 1
        - require:
            - firewall: iptables-cloud-metadata-firewall-tcp-root-{{ family }}
{% endfor %}
{% else %}
iptables-cloud-metadata-firewall-tcp:
    firewall.append:
        - chain: OUTPUT
        - protocol: tcp
        - dport: 80
        - destination: 169.254.169.254
        - match:
            - comment
        - comment: 'iptables.cloud_metadata: Allow http to metadata service'
        - jump: ACCEPT
{% endif %}


iptables-cloud-metadata-firewall-udp:
    firewall.append:
        - chain: OUTPUT
        - protocol: udp
        - dports: 67,68,123 # DHCP and NTP
        - destination: 169.254.169.254
        - match:
            - comment
        - comment: 'iptables.cloud_metadata: Allow NTP and DHCP to metadata service'
        - jump: ACCEPT
