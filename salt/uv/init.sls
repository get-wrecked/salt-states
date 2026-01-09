{% set uv = pillar.get('uv', {}) %}
{% set version_info = uv.get('version_info', '0.9.22 sha256=e170aed70ac0225feee612e855d3a57ae73c61ffb22c7e52c3fd33b87c286508') %}
{% set version, checksum = version_info.split() %}

uv:
  archive.extracted:
    - name: /usr/local/bin
    - source: https://github.com/astral-sh/uv/releases/download/{{ version }}/uv-x86_64-unknown-linux-gnu.tar.gz
    - source_hash: {{ checksum }}
    - options: --strip-components=1
    - enforce_toplevel: False
