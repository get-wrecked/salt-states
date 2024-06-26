{% set jenkins = pillar.get('jenkins', {}) %}
{% set extra_groups = jenkins.get('extra_groups', []) %}

include:
    - .agent_pillar_check


jenkins-agent-deps:
    pkg.installed:
        - pkgs:
            - openjdk-11-jre
            - openjdk-11-jdk
        - unless: java -version 2>&1 | head -1 | grep 1.11


jenkins-agent-ssh-group:
    group.present:
        - name: ssh


jenkins-agent-user:
    group.present:
        - name: jenkins

    user.present:
        - name: jenkins
        - system: True
        - empty_password: True
        - gid_from_name: True
        - fullname: Jenkins Agent
        - groups:
            - ssh
            {% for group in extra_groups %}
            - {{ group  }}
            {% endfor %}
        - require:
            - group: jenkins-agent-ssh-group
            - group: jenkins-agent-user

    ssh_auth.present:
        - user: jenkins
        - names:
            - {{ jenkins.get('master_ssh_pubkey') }}
        - require:
            - user: jenkins-agent-user

    file.directory:
        # Add a private temp directory to avoid polluting the global tmp which might be
        # memory-backed and noexec
        - name: ~jenkins/tmp
        - user: jenkins
        - group: jenkins
