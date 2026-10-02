"""An optional HTTP wrapper around witness_core, for deployments that
want WITNESS as a standalone pre-execution admission-control service
(a sidecar, or a shared gate multiple agent frameworks call into)
rather than an embedded library call. See service/app.py.

Nothing in witness_core or adapters depends on this package -- the
zero-dependency core and the AIOpsLab adapters work identically with
or without it installed. Install with `pip install -e '.[service]'`.
"""
