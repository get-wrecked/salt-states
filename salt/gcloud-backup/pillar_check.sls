#!py

def run():
    '''Validate that the gcloud-backup pillar has the necessary config.'''
    gcloud_backup = __salt__['mdl_saltdata.resolve_leaf_values'](__pillar__.get('gcloud-backup', {}))
    assert 'bucket_name' in gcloud_backup, (
        'pillar gcloud-backup:bucket_name required but missing')
    assert 'targets' in gcloud_backup, (
        'pillar gcloud-backup:targets is required')

    return {}
