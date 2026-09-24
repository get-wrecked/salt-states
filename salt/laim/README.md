Laim
====

Installs and configures laim, but does not install a handler. You should write your own state that deploys the handler and include this state.

Values under `laim:config` can reference other pillar values by suffixing the key
with `_pillar`, ie `honeycomb-key_pillar: terraform:laim_honeycomb_key` becomes
`honeycomb-key` with the value of `terraform:laim_honeycomb_key`. See
`mdl_saltdata.resolve_leaf_values` for details.
