# Excerpt, not runnable.
# Source: Grantgazvoda-alt/eve-achilles — eve_achilles_harness.py (ZeroCopyScopeGate)
# Staged locally only; not published. Bodies trimmed or stubbed.

"""Fail-closed scope gate (excerpt). DNS, file I/O, and override loaders stubbed."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


class ZeroCopyScopeGate:
    """Scope gate with IP / hostname / CIDR-aware matching.

    Deny always wins over allow. The normal allow gate uses
    `_match(..., require_all=True)` so a hostname in scope only by DNS
    must have EVERY resolved address in scope (fail closed on rebinding).
    admin_override and cred_allow keep any-address matching; that
    asymmetry is intentional (see tests/test_scope_rebinding.py in source).

    Init / load_scope / owner-override file loaders are omitted here.
    """

    def __init__(self, scope_file: str = "scope.json") -> None:
        self.raw_allow: Set[str] = set()
        self.allow_hosts: Set[str] = set()
        self.allow_nets: list = []
        self.allow_wildcards: List[str] = []
        self.wildcard: bool = False
        self.deny_raw: Set[str] = set()
        self.override_raw: Set[str] = set()
        self.override_hosts: Set[str] = set()
        self.override_nets: list = []
        self.cred_allow: Set[str] = set()
        self.cred_wildcard: bool = False
        self.cred_hosts: Set[str] = set()
        self.cred_nets: list = []
        self.owned_targets: Set[str] = set()
        self.owned_misconfigured: bool = False
        # Tests inject simulated DNS here; no network in this excerpt.
        self._resolve_cache: Dict[str, Set[str]] = {}
        self.scope_file = str(scope_file)

    def _resolve(self, host: str) -> Set[str]:
        """Source resolves + caches DNS with a TTL. Excerpt returns the test cache only."""
        return set(self._resolve_cache.get(host, set()))

    def _norm_host(self, target: str) -> str:
        # Source strips URL/port wrappers. Excerpt: lowercase identity.
        return str(target or "").strip().lower()

    def is_denied(self, target: str, tool: str = "") -> bool:
        """True if target matches any out-of-scope deny/exclusion rule."""
        if not self.deny_raw or not target:
            return False
        t_raw = str(target or "").strip().lower()
        host = self._norm_host(t_raw)
        return t_raw in self.deny_raw or host in self.deny_raw or (
            bool(tool) and f"{host}:{tool}" in self.deny_raw
        )

    def _match(self, host: str, hosts: Set[str], nets: list, require_all: bool = False) -> bool:
        """Is `host` covered by (hosts, nets)?

        require_all=False (admin_override / cred_allow): ANY address may match.
        require_all=True (normal allow gate): a hostname matched ONLY by DNS
        must have EVERY resolved address in scope, or we refuse it.
        """
        import ipaddress
        if host in hosts:
            return True
        is_literal = True
        ips = set()
        try:
            ips.add(str(ipaddress.ip_address(host)))
        except ValueError:
            is_literal = False
            ips |= self._resolve(host)

        def _ip_in_scope(ip: str) -> bool:
            try:
                ipobj = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if any(ipobj in net for net in nets):
                return True
            for hname in hosts:
                if ip in self._resolve(hname):
                    return True
            return False

        if not ips:
            return False
        if require_all and not is_literal:
            return all(_ip_in_scope(ip) for ip in ips)
        return any(_ip_in_scope(ip) for ip in ips)

    def _owner_allows(self, target: str, host: str, tool: str = "") -> bool:
        """Source checks a principal-gated owner override. Excerpt: always False."""
        return False

    def _named_target_permitted(self, target: str, tool: str = "") -> bool:
        """Source consults named-target mode. Excerpt: always False."""
        return False

    def _endpoint_matches(self, target: str, origins, paths, host_ports) -> bool:
        """URL/origin matching omitted from excerpt."""
        return False

    def decide(self, target: str, tool: str = "") -> Tuple[bool, str]:
        if self.is_denied(target, tool):
            return False, "denied"
        if self.wildcard:
            return True, "wildcard"
        host = self._norm_host(target)
        if (
            f"{target}:{tool}" in self.raw_allow
            or f"{host}:{tool}" in self.raw_allow
            or target in self.raw_allow
            or host in self.raw_allow
        ):
            return True, "in_scope"
        if self._match(host, self.allow_hosts, self.allow_nets, require_all=True):
            return True, "in_scope"
        if self.allow_wildcards and host:
            for root in self.allow_wildcards:
                if host == root or host.endswith("." + root):
                    return True, "in_scope_wildcard"
        if self._owner_allows(target, host, tool):
            return True, "owner_override"
        if (
            target in self.override_raw
            or host in self.override_raw
            or self._match(host, self.override_hosts, self.override_nets)
        ):
            return True, "admin_override"
        return False, "blocked"

    def check(self, target: str, tool: str = "") -> bool:
        return self.decide(target, tool)[0]

    def cred_permitted(self, target: str) -> bool:
        """Credentialed-testing list is independent of decide(); empty means no."""
        if self.is_denied(target):
            return False
        if self.cred_wildcard:
            return True
        if not self.cred_allow or not target:
            return False
        host = self._norm_host(target)
        if target in self.cred_allow or host in self.cred_allow:
            return True
        return self._match(host, self.cred_hosts, self.cred_nets)
