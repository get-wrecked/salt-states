{% from 'rabbitmq/map.jinja' import rabbitmq with context %}

include:
    - apt-transport-https


rabbitmq-erlang-repo:
    pkgrepo.managed:
        - name: deb https://dl.cloudsmith.io/public/rabbitmq/rabbitmq-erlang/deb/debian {{ grains.oscodename }} main
        - key_url: salt://rabbitmq/release-key-erlang.asc

    {% if 'erlang_version' in rabbitmq %}
    file.managed:
        - name: /etc/apt/preferences.d/erlang
        - contents: |
            Package: erlang*
            Pin: version {{ rabbitmq.erlang_version }}
            Pin-Priority: 1000

    cmd.watch:
        - name: apt-get update -y
        - watch:
            - file: rabbitmq-erlang-repo
        - require_in:
            - pkg: rabbitmq-server
    {% endif %}


rabbitmq-server:
    pkgrepo.managed:
        - name: deb https://packagecloud.io/rabbitmq/rabbitmq-server/debian/ {{ grains.oscodename }} main
        - key_url: salt://rabbitmq/release-key-rabbitmq.asc

    pkg.installed:
        {% if 'version' in rabbitmq %}
        - version: {{ rabbitmq.version }}
        {% endif %}
        - require:
            - pkgrepo: rabbitmq-erlang-repo
            - pkgrepo: rabbitmq-server

    service.running:
        - require:
            - pkg: rabbitmq-server

    # Remove the guest user
    rabbitmq_user.absent:
        - name: guest
        - require:
            - pkg: rabbitmq-server


rabbitmq-old-repos:
    pkgrepo.absent:
        - names:
            - deb https://dl.bintray.com/rabbitmq-erlang/debian buster erlang
            - deb https://dl.bintray.com/rabbitmq/debian buster main
        - keyid: 6B73A36E6026DFCA


{% for family in ('ipv4', 'ipv6') %}
rabbitmq-firewall-inbound-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: INPUT
        - protocol: tcp
        - match:
            - comment
        - dports: 5672
        - comment: 'rabbitmq: Allow plaintext AMQP'
        - jump: ACCEPT
{% endfor %}
