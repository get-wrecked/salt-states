{% from 'metadata-proxy/map.jinja' import listeners with context %}

include:
    - .pillar_check
    # With the proxy pillar set, this allows root to the metadata server and
    # rejects every other user; the proxy's own allow below goes between them
    - iptables.cloud_metadata


metadata-proxy:
    pkg.installed:
        - name: python3

    user.present:
        - name: metadata-proxy
        - system: True
        - shell: /usr/sbin/nologin
        - home: /nonexistent
        - createhome: False

    file.managed:
        - name: /usr/local/bin/metadata-proxy
        - source: salt://metadata-proxy/metadata_proxy.py
        - mode: 755

    service.running:
        - enable: True
        - require:
            - pkg: metadata-proxy
            - file: metadata-proxy-config
            - file: metadata-proxy-service
        - watch:
            - file: metadata-proxy
            - file: metadata-proxy-config
            - file: metadata-proxy-service


metadata-proxy-config:
    file.managed:
        - name: /etc/metadata-proxy.json
        - user: root
        - group: metadata-proxy
        - mode: 640
        - contents: |
            {{ {'listeners': listeners}|json|indent(12) }}
        - require:
            - user: metadata-proxy


metadata-proxy-service:
    file.managed:
        - name: /etc/systemd/system/metadata-proxy.service
        - contents: |
            [Unit]
            Description=Per-user GCE metadata proxy
            After=network-online.target
            Wants=network-online.target

            [Service]
            User=metadata-proxy
            Group=metadata-proxy
            ExecStart=/usr/bin/python3 /usr/local/bin/metadata-proxy
            # Mapped users have no credentials while this is down, root is unaffected
            Restart=always
            RestartSec=2

            # The identity ports are privileged, so that no other local user can
            # bind one while the proxy is down and answer the redirected requests
            AmbientCapabilities=CAP_NET_BIND_SERVICE
            CapabilityBoundingSet=CAP_NET_BIND_SERVICE
            NoNewPrivileges=true
            ProtectSystem=strict
            ProtectHome=true
            PrivateTmp=true
            PrivateDevices=true
            ProtectKernelTunables=true
            ProtectKernelModules=true
            ProtectControlGroups=true
            RestrictAddressFamilies=AF_INET AF_INET6
            RestrictNamespaces=true
            LockPersonality=true
            MemoryDenyWriteExecute=true
            SystemCallArchitectures=native

            [Install]
            WantedBy=multi-user.target

    cmd.watch:
        - name: systemctl daemon-reload
        - watch:
            - file: metadata-proxy-service
        - watch_in:
            - service: metadata-proxy


# The proxy reads the VM's token from the real metadata server and mints the
# mapped users' tokens through the IAM Credentials API.
{% for family in ('ipv4', 'ipv6') %}
metadata-proxy-firewall-outgoing-https-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: tcp
        - dport: 443
        - match:
            - comment
            - owner
        - comment: "metadata-proxy: Allow outgoing HTTPS"
        - uid-owner: metadata-proxy
        - jump: ACCEPT
        - require:
            - user: metadata-proxy


{% for protocol in ('tcp', 'udp') %}
metadata-proxy-firewall-outgoing-dns-{{ family }}-{{ protocol }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: {{ protocol }}
        - dport: 53
        - destination: system_dns
        - match:
            - comment
            - owner
        - comment: "metadata-proxy: Allow outgoing DNS"
        - uid-owner: metadata-proxy
        - jump: ACCEPT
        - require:
            - user: metadata-proxy
{% endfor %}
{% endfor %}


# Each mapped user's metadata traffic goes to that user's identity port instead
# of the real server. The redirected packets leave on lo, which the iptables
# state allows.
{% for listener in listeners %}
metadata-proxy-firewall-redirect-{{ listener.user }}:
    firewall.append:
        - table: nat
        - family: ipv4
        - chain: OUTPUT
        - protocol: tcp
        - destination: 169.254.169.254
        - dport: 80
        - match:
            - comment
            - owner
        - comment: "metadata-proxy: {{ listener.user }} gets {{ listener.service_account }}"
        - uid-owner: {{ listener.user }}
        - jump: REDIRECT
        - to-ports: {{ listener.port }}


# The redirect only decides where the user's own traffic lands; anyone could
# connect to the port directly, since the iptables state allows all of lo. So
# nobody else may open a connection to it. Ordered ahead of that lo rule. The
# proxy checks the caller's uid as well, so a mistake here fails closed.
metadata-proxy-firewall-port-owner-{{ listener.user }}:
    firewall.append:
        - family: ipv4
        - chain: OUTPUT
        - out-interface: lo
        - protocol: tcp
        - dport: {{ listener.port }}
        - syn: ''
        - match:
            - comment
            - owner
        - comment: "metadata-proxy: Only {{ listener.user }} may connect to its identity port"
        - uid-owner: '!{{ listener.user }}'
        - jump: REJECT
        - reject-with: tcp-reset
        - order: 1
{% endfor %}


# The proxy reaches the real metadata server, and so the VM's own identity,
# like root does. Ordered between iptables.cloud_metadata's root allow and
# its reject.
metadata-proxy-firewall-allow-upstream:
    firewall.append:
        - family: ipv4
        - chain: OUTPUT
        - protocol: tcp
        - destination: 169.254.169.254
        - dport: 80
        - match:
            - comment
            - owner
        - comment: "metadata-proxy: Allow metadata-proxy to the real metadata server"
        - uid-owner: metadata-proxy
        - jump: ACCEPT
        - order: 1
        - require:
            - user: metadata-proxy
            - firewall: iptables-cloud-metadata-firewall-tcp-root-ipv4
        - require_in:
            - firewall: iptables-cloud-metadata-firewall-tcp-reject-ipv4
