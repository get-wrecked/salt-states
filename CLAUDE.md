# Claude Code Guidelines for salt-states

## Salt State Patterns

### Version-Managed Resources

When creating states for versioned tools (binaries, packages, etc.):

- ✅ DO: Use `source_hash` to detect version changes
- ❌ DON'T: Use `if_missing` - it prevents version updates
- ✅ DO: Test that updating the version in pillar triggers a re-run
- ✅ DO: Verify idempotency (second run should show no changes)

### Archive Extraction

For `archive.extracted` states:
- Default is `keep_source: True` (caches archive, avoids re-downloads)
- Use `keep_source: False` only if disk space is critical (causes re-download on each run)
- Use `options: --strip-components=1` to extract directly without parent directory
- Archives typically preserve file permissions - verify before adding chmod

### Testing States

Test with Docker:
```bash
docker build -t salt-states .
docker run --rm salt-states <state-name>  # Run state once
```

To verify idempotency (MUST run both invocations in same container):
```bash
docker run --rm --entrypoint /bin/bash salt-states -c \
  "salt-call state.sls <state> && echo '=== Second run ===' && salt-call state.sls <state>"
```

## State Structure Patterns

### Namespacing

**ALWAYS** prefix all state IDs with the state name:
- In `postgres/init.sls`: use `postgres-*` (e.g., `postgres-config`, `postgres-service`)
- In `postgres/client.sls`: use `postgres-client-*` (e.g., `postgres-client-package`)
- In `nginx/init.sls`: use `nginx-*` (e.g., `nginx-certificates-dir`, `nginx-firewall-ipv4`)

**Why**: Prevents conflicts when states are included by other states, makes dependencies clear

### Pillar Data with Defaults (map.jinja)

For states with configurable options, create a `map.jinja` file:

```jinja
{% set mystate = salt['grains.filter_by']({
    'base': {
        'port': 8080,
        'timeout': 30,
        'enable_tls': True,
    },
}, merge=salt['pillar.get']('mystate'), base='base') %}
```

Import in your state file:
```jinja
{% from 'mystate/map.jinja' import mystate with context %}

mystate-config:
  file.managed:
    - name: /etc/mystate/config.yml
    - contents: |
        port: {{ mystate.port }}
        timeout: {{ mystate.timeout }}
```

**Benefits**: Centralized defaults, easy to reference from multiple files, pillar values override defaults

### Pillar Validation (pillar_check.sls)

For required pillar values, create a `pillar_check.sls`:

```python
#!py

def run():
    """Validate pillar data for mystate."""
    mystate = __pillar__.get('mystate', {})

    assert 'required_field' in mystate, 'Must define mystate:required_field'
    assert mystate.get('port', 0) > 0, 'Port must be positive'

    return {}
```

Include in your `init.sls`:
```jinja
include:
    - .pillar_check
```

**Why**: Fail fast with clear error messages instead of cryptic failures later

### Firewall Rules

**ALWAYS** add firewall rules for services that use the network. Follow these patterns:

```jinja
# Inbound rules (services that listen)
{% for family in ('ipv4', 'ipv6') %}
mystate-firewall-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: INPUT
        - proto: tcp
        - dport: {{ mystate.port }}
        - match:
            - comment
        - comment: "mystate: Allow incoming connections"
        - jump: ACCEPT
{% endfor %}

# Outbound rules (services that make external requests)
{% for family in ('ipv4', 'ipv6') %}
mystate-firewall-outbound-{{ family }}:
    firewall.append:
        - family: {{ family }}
        - chain: OUTPUT
        - proto: tcp
        - dport: 443
        - match:
            - comment
            - owner
        - comment: "mystate: Allow outgoing HTTPS"
        - uid-owner: root
        - jump: ACCEPT
{% endfor %}
```

**Key points**:
- Always handle both IPv4 and IPv6
- Use descriptive comments with state name prefix
- Use `owner` match for outbound rules to limit which users can access
- Include protocol-specific rules (TCP/UDP for DNS, etc.)

### Service Management

For services with config files:

```jinja
mystate:
    pkg.installed:
        - name: mystate

    file.managed:
        - name: /etc/mystate/config.yml
        - source: salt://mystate/config.yml
        - template: jinja
        - require:
            - pkg: mystate

    service.running:
        - name: mystate
        - watch:
            - file: mystate
            - file: mystate-extra-config
```

**Pattern**: Use `watch` to automatically restart service when configs change

### Secrets Management

**NEVER** show secrets in Salt output:

```jinja
mystate-secret-key:
    file.managed:
        - name: /etc/mystate/secret.key
        - contents_pillar: mystate:secret_key
        - mode: 600
        - show_changes: False  # CRITICAL: Don't log secret changes
```

**Use `show_changes: False` for**:
- Private keys
- Passwords
- API tokens
- Certificates (private keys only, not public certs)

### Repository Management

When adding third-party package repositories:

```jinja
mystate-repo-key:
    file.managed:
        - name: /usr/share/keyrings/mystate-keyring.gpg
        - source: salt://mystate/release-key.gpg

mystate-repo:
    file.managed:
        - name: /etc/apt/sources.list.d/mystate.list
        - contents: deb [signed-by=/usr/share/keyrings/mystate-keyring.gpg] https://repo.example.com {{ grains.oscodename }} main
        - require:
            - file: mystate-repo-key

# Optional: Prevent repo from upgrading other packages
mystate-repo-preferences:
    file.managed:
        - name: /etc/apt/preferences.d/mystate.pref
        - contents: |
            Package: *
            Pin: origin repo.example.com
            Pin-Priority: 1

            Package: mystate
            Pin: origin repo.example.com
            Pin-Priority: 500
```

**Why**: Restricts repository key scope, prevents unintended package upgrades

### Conditional Includes

Include other states only when needed:

```jinja
include:
    - .pillar_check
{% if mystate.get('enable_backups', False) %}
    - s3-uploader
{% endif %}
```

### Jinja Loops for Repetitive Tasks

Use loops to avoid duplication:

```jinja
# Multiple firewall rules
{% for protocol in ('tcp', 'udp') %}
mystate-firewall-dns-{{ protocol }}:
    firewall.append:
        - proto: {{ protocol }}
        - dport: 53
{% endfor %}

# Multiple key types
{% for key_type in ('rsa', 'ed25519', 'ecdsa') %}
{% if 'host_%s_key' % key_type in mystate %}
mystate-host-key-{{ key_type }}:
    file.managed:
        - name: /etc/mystate/{{ key_type }}_key
        - contents_pillar: mystate:host_{{ key_type }}_key
{% endif %}
{% endfor %}
```
