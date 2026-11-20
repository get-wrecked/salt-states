#!py

RESERVED_USERS = ('root', 'metadata-proxy')
# The identity ports must stay privileged, so that no other local user can bind
# one while the proxy is down; the unit grants it CAP_NET_BIND_SERVICE for them
MAX_PORT = 1023


def run():
    """Validate pillar data for metadata-proxy."""
    config = __pillar__.get('metadata-proxy', {})
    identities = config.get('identities', {})
    default_users = config.get('default_compute_sa_users', [])

    assert isinstance(identities, dict), (
        'metadata-proxy:identities must map local users to service account emails')
    for user, service_account in identities.items():
        assert isinstance(service_account, str) and '@' in service_account, (
            'metadata-proxy:identities:%s must be a service account email, got %r'
            % (user, service_account))

    assert isinstance(default_users, list), (
        'metadata-proxy:default_compute_sa_users must be a list of local users')

    assert identities or default_users, (
        'metadata-proxy needs at least one user in identities or default_compute_sa_users')

    both = set(identities) & set(default_users)
    assert not both, (
        'metadata-proxy: users in both identities and default_compute_sa_users: %s'
        % ', '.join(sorted(both)))

    reserved = set(RESERVED_USERS) & (set(identities) | set(default_users))
    assert not reserved, (
        'metadata-proxy: %s reach the real metadata server and cannot be mapped'
        % ', '.join(sorted(reserved)))

    base_port = config.get('base_port', 900)
    last_port = base_port + len(identities) + len(default_users) - 1
    assert 1 <= base_port and last_port <= MAX_PORT, (
        'metadata-proxy: the identity ports %d-%d must all be within 1-%d'
        % (base_port, last_port, MAX_PORT))

    return {}
