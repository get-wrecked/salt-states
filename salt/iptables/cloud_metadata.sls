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
