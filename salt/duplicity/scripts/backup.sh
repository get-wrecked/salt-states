{% from 'duplicity/map.jinja' import duplicity with context -%}
{% set targets = duplicity.get('targets', {}) -%}
{% set config = salt['mdl_saltdata.resolve_leaf_values'](targets.get(backupname, {})) -%}


#!/bin/sh

#############################################
# File managed by salt state duplicity.cron #
#############################################

export PASSPHRASE='{{ config.passphrase }}'

duplicity \
    --verbosity warning \
    --no-print-statistics \
    --volsize {{ duplicity.get('volume_size', '700') }} \
    --gpg-options="--cipher-algo=AES256 --digest-algo=SHA512 --s2k-digest-algo=SHA512" \
    --asynchronous-upload \
    --allow-source-mismatch \
    --max-blocksize 65536 \
    --name {{ backupname }} \
    --s3-use-new-style \
    --archive-dir /var/cache/duplicity \
    --tempdir "{{ duplicity.tempdir }}" \
    {% for option in config.get('options', []) -%}
    {{ option }} \
    {% endfor -%}
    {{ config.source_dir }} \
    {{ config.target }}
