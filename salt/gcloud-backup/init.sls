include:
    - .pillar_check
    - cronic

gcloud-backup-deps:
    pkg.installed:
        - name: python3-virtualenv


gcloud-backup-config:
    file.managed:
        - name: /etc/gcloud-backup.json
        - contents: '{{ salt["mdl_saltdata.resolve_leaf_values"](pillar.get("gcloud-backup")) | json }}'
        - show_changes: False
        - user: root
        - group: root
        - mode: 640

gcloud-backup:
    virtualenv.managed:
        - name: /opt/venvs/gcloud-backup
        - pip_pkgs:
            - google-cloud-storage
        - require:
            - pkg: gcloud-backup-deps

    file.managed:
        - name: /usr/bin/gcloud-backup.py
        - source: salt://gcloud-backup/backup.py
        - mode: 750
        - user: root
        - group: root


# This could be under the gcloud-backup id, but keeping it on a separate one to
# enable it be excluded when restoring
gcloud-backup-cron:
    cron.present:
        - name: cronic /opt/venvs/gcloud-backup/bin/python3 /usr/bin/gcloud-backup.py /etc/gcloud-backup.json
        - identifier: gcloud-backup
        - minute: random
        - hour: 0
