from collections import defaultdict
import difflib
import jinja2
import json
import os
import subprocess

RULES_TEMPLATE = jinja2.Template('''
{% if nat_rules %}
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
{% for chain in nat_chains|default([]) -%}
:{{ chain }} - [0:0]
{% endfor %}

{% for rule in nat_rules|default([]) -%}
{{ rule }}
{% endfor -%}

COMMIT
{% endif %}


*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
{% for chain in filter_chains|default([]) -%}
:{{ chain }} - [0:0]
{% endfor %}

{% for rule in filter_rules|default([]) -%}
{{ rule }}
{% endfor -%}

COMMIT
''')


def _add_rule(target_file, key, rule):
    # Each rule is stored as a single line in the file, as a json
    # object with table -> rule
    object_to_store = {
        key: rule,
    }
    with open(target_file, 'a') as fh:
        json.dump(object_to_store, fh)
        fh.write('\n')



def append(name, chain='INPUT', table='filter', family='ipv4', **kwargs):
    assert family in ('ipv4', 'ipv6')
    assert table in ('filter', 'nat')

    partial_rule = __salt__['iptables.build_rule'](**kwargs)
    full_rule = '-A %s %s' % (chain, partial_rule)

    cachedir = __opts__['cachedir']
    file_target = os.path.join(cachedir, 'firewall-rules-%s.json' % family[-2:])
    _add_rule(file_target, '%s_rules' % table, full_rule)

    return {
        'name': name,
        'comment': '',
        'result': True,
        'changes': '',
    }


def chain_present(name, table='filter', family='ipv4', **kwargs):
    assert table in ('filter', 'nat')
    assert family in ('ipv4', 'ipv6')

    cachedir = __opts__['cachedir']
    file_target = os.path.join(cachedir, 'firewall-rules-%s.json' % family[-2:])
    _add_rule(file_target, '%s_chains' % table, name)

    return {
        'name': name,
        'result': True,
        'changes': '',
        'comment': '',
    }


def _get_rules(path):
    try:
        fh = open(path)
    except OSError:
        return {}
    with fh:
        all_rules = defaultdict(list)
        for line in fh:
            parsed_line = json.loads(line)
            for key, value in parsed_line.items():
                all_rules[key].append(value)
        return all_rules


def apply(name):
    cachedir = __opts__['cachedir']
    v4_file_target = os.path.join(cachedir, 'firewall-rules-v4.json')
    v6_file_target = os.path.join(cachedir, 'firewall-rules-v6.json')

    v4_result, v4_stderr, v4_changes = _apply_rule_for_family('rules.v4',
        _get_rules(v4_file_target), 'iptables-restore')
    v6_result, v6_stderr, v6_changes = _apply_rule_for_family('rules.v6',
        _get_rules(v6_file_target), 'ip6tables-restore')

    # Remove temp files on disk to prevent leaking rules between runs
    for temp_file in (v4_file_target, v6_file_target):
        os.remove(temp_file)

    comment = []
    if v4_stderr:
        comment.append(v4_stderr)
    if v6_stderr:
        comment.append(v6_stderr)

    changes = []
    if v4_changes:
        changes.append(v4_changes)
    if v6_changes:
        changes.append(v6_changes)

    return {
        'name': name,
        'comment': '\n'.join(comment),
        'result': True if v4_result is 0 and v6_result is 0 else False,
        'changes': '\n'.join(changes),
    }


def _apply_rule_for_family(filename, context, restore_command):
    rendered_rules = RULES_TEMPLATE.render(context)

    # iptables-restore fails to parse if the rules doesnt end with newline
    if not rendered_rules[-1] == '\n':
        rendered_rules += '\n'

    # Ensure that the target directory exists
    if not os.path.exists('/etc/iptables'):
        os.makedirs('/etc/iptables')

    # First, read old content so that we can compute a diff (but might not exist already)
    target_file = '/etc/iptables/%s' % filename
    try:
        with open(target_file) as fh:
            old_content = fh.readlines()
    except IOError:
        old_content = []

    with open(target_file, 'w') as fh:
        fh.write(rendered_rules)

    new_content = [line + '\n' for line in rendered_rules[:-1].split('\n')]
    changes = ''.join(difflib.unified_diff(old_content, new_content,
        fromfile=target_file, tofile=target_file))

    restore_process = subprocess.Popen([restore_command], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = restore_process.communicate(rendered_rules)
    return (restore_process.wait(), stderr, changes)