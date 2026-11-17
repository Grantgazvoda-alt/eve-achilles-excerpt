# Excerpt, not runnable.
# Source: Grantgazvoda-alt/eve-achilles — tests/test_scope_rebinding.py
# Staged locally only; not published. Bodies trimmed or stubbed.

"""Illustrative fixture only: DNS is simulated; no network. Assertion bodies stubbed.

A hostname in scope only by DNS must have EVERY resolved address in scope.
mixed.test -> {in-scope IP, attacker IP} must fail closed.
"""

DNS = {
    "allin.test": {"10.0.0.5", "10.0.0.9"},
    "mixed.test": {"10.0.0.5", "66.66.66.66"},
    "allout.test": {"66.66.66.66"},
    "dead.test": set(),
}

# Source primes ZeroCopyScopeGate._resolve_cache with DNS above (no network)
# and asserts allow(allin.test) / deny(mixed.test, allout.test, dead.test).
# Full 22/22 cases remain in the source test file and are not copied here.
