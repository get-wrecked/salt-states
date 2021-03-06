{% set honeytail = pillar.get('honeytail', {}) %}
{% set version_info = honeytail.get('version_info', '1.762 sha256=d7bed8a005cbc6a34b232c54f0f84b945f0bb90905c67f85cceaedee9bbbad1e') %}
{% set version, checksum = version_info.split() %}

include:
    - .pillar_check


honeytail-deb:
    file.managed:
        - name: /usr/local/src/honeytail-{{ version }}.deb
        - source: https://honeycomb.io/download/honeytail/linux/honeytail_{{ version }}_amd64.deb
        - source_hash: {{ checksum }}

    cmd.wait:
        - name: dpkg -i /usr/local/src/honeytail-{{ version }}.deb
        - watch:
            - file: honeytail-deb


honeytail:
    file.managed:
        - name: /etc/honeytail/honeytail.conf
        - source: salt://honeytail/honeytail.conf
        - template: jinja
        - show_changes: False
        - user: root
        - group: adm
        - mode: 640
        - require:
            - cmd: honeytail-deb

    init_script.managed:
        - systemd: salt://honeytail/job-systemd

    cmd.watch:
        - name: systemctl --system daemon-reload
        - watch:
            - init_script: honeytail

    service.running:
        - watch:
            - cmd: honeytail-deb
            - file: honeytail
            - init_script: honeytail

    user.present:
        - name: honeycomb
        - groups:
            - adm
        - require:
            - cmd: honeytail-deb


{% for family in ('ipv4', 'ipv6') %}

{% for protocol in ('udp', 'tcp') %}
honeytail-outgoing-firewall-dns-{{ family }}-{{ protocol }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: {{ protocol }}
        - dport: 53
        - destination: system_dns
        - match:
            - comment
            - owner
        - comment: 'honeytail: Allow outgoing DNS'
        - uid-owner: honeycomb
        - require:
            - user: honeytail
        - jump: ACCEPT
{% endfor %}

honeytail-outgoing-firewall-events-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - protocol: tcp
        - dport: 443
        # honeycomb doesn't publish IP ranges, thus have to allow arbitrary outgoing https
        - match:
            - comment
            - owner
        - comment: 'honeytail: Allow sending events over https'
        - uid-owner: honeycomb
        - require:
            - user: honeytail
        - jump: ACCEPT
{% endfor %}
