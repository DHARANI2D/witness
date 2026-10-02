"""Claim-action licensing (WITNESS mechanism 4).

Corroboration (mechanism 3) proves a claim is *true*; it says nothing
about whether that claim is the *right reason* for a specific action.
A genuinely corroborated `error_rate_elevated` claim is real evidence
of elevated 404s -- it is not evidence that disabling an account,
restarting an unrelated service, or changing TLS config is the correct
response to it. Lineage (mechanism 2) separately proves an action's
literal arguments are trustworthy; it says nothing about whether the
action is justified by any evidence at all. A remediation can pass
both of the first two mechanisms -- a real corroborated claim, real
trusted arguments -- and still be the wrong fix for the evidence it
cites, because nothing previously checked that the claim and the
action actually belong together. This mechanism closes that gap: each
action verb has an explicit contract naming the predicates that may
license it, and a remediation is admitted only if at least one of its
*corroborated* claims matches that verb's contract. A verb with no
registered contract is always held -- the same fail-safe-by-default
posture this engine already applies to an unresolved claim source
(`corroboration.py`) or an unregistered predicate.
"""

from __future__ import annotations


class LicenseCatalog:
    """Registry mapping an action verb to the set of predicates whose
    corroboration may justify taking that action."""

    def __init__(self):
        self._contracts: dict[str, frozenset[str]] = {}

    def register(self, verb: str, predicates) -> None:
        predicates = frozenset(predicates)
        if not predicates:
            raise ValueError("a verb's contract must name at least one predicate")
        self._contracts[verb] = predicates

    def has_contract(self, verb: str) -> bool:
        return verb in self._contracts

    def licenses(self, verb: str, predicate: str) -> bool:
        """True iff `predicate`'s corroboration is sufficient grounds
        for `verb`. A verb with no contract at all returns False for
        every predicate -- fail safe, not fail open."""
        return predicate in self._contracts.get(verb, frozenset())

    def verbs(self) -> list[str]:
        return sorted(self._contracts)


def build_default_license_catalog() -> LicenseCatalog:
    """The 5 action-contract pairs this prototype's closed 5-predicate
    vocabulary (witness_core/catalog.py) currently licenses. Every
    other verb the shell-command classifier can produce (26 of the 31
    total -- see shell_parser.py's distinct verb strings) has no
    contract and is therefore always held via `LicenseCatalog.licenses`'s
    fail-safe default, regardless of how well-corroborated any claim
    attached to it is.

    Each pairing matches an existing scenario or security-evaluation
    fixture already in this repo (cpu_saturation_benign.py,
    admin_lockout_attack.py, and the `legitimate_*` families in
    scripts/security_evaluation.py) -- this mechanism was added to
    match behavior already exercised by the existing test corpus, not
    invented against it.
    """
    catalog = LicenseCatalog()
    catalog.register("restart_service", {"cpu_saturated"})
    catalog.register("modify_tls_config", {"protocol_unsupported"})
    catalog.register("add_repo", {"error_rate_elevated"})
    catalog.register("install_package", {"package_version_is"})
    catalog.register("disable_account", {"session_from_new_geo"})
    return catalog
