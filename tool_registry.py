# Excerpt, not runnable.
# Source: Grantgazvoda-alt/eve-achilles — eve_achilles_harness.py (ToolRegistry)
# Staged locally only; not published. Bodies trimmed or stubbed.

"""Registry chokepoint: gate + ledger before any tool body. Tool bodies omitted."""

from __future__ import annotations

from typing import Callable, Optional

from zero_copy_scope_gate import ZeroCopyScopeGate


class BatchedLedger:
    """Append-only audit ledger. Hash-chain / HMAC implementation omitted."""

    def record(self, entry: dict, immediate: bool = False) -> bool:
        return True


def _safe_ledger_record(ledger: BatchedLedger, entry: dict, immediate: bool = True) -> bool:
    try:
        return ledger.record(entry, immediate=immediate)
    except Exception:
        return False


class ToolRegistry:
    def __init__(self, gate: ZeroCopyScopeGate, ledger: BatchedLedger) -> None:
        self.gate = gate
        self.ledger = ledger
        self.tools: dict = {}

    def register(self, name: str, fn: Callable) -> None:
        if not name or not callable(fn):
            return
        self.tools[name] = fn

    def _gate_and_log(self, target: str, tool: str) -> bool:
        allowed, reason = self.gate.decide(target, tool)
        recorded = _safe_ledger_record(
            self.ledger,
            {"tool": tool, "target": target, "allowed": allowed, "reason": reason},
            immediate=(not allowed or reason in (
                "admin_override", "named_target",
                "owner_override", "override_rejected_non_owner",
            )),
        )
        return allowed and recorded

    def call(self, tool: str, target: str, args: Optional[list] = None, *,
             pinned_binary_only: bool = False) -> dict:
        allowed, reason = self.gate.decide(target, tool)
        recorded = _safe_ledger_record(
            self.ledger,
            {"tool": tool, "target": target, "allowed": allowed, "reason": reason},
            immediate=(not allowed or reason in (
                "admin_override", "named_target",
                "owner_override", "override_rejected_non_owner",
            )),
        )
        if not allowed or not recorded:
            return {"error": "scope blocked", "target": target, "reason": reason}
        # Scanner / tool dispatch (_nmap, _sqlmap, _ffuf, ...) omitted from excerpt.
        raise NotImplementedError("excerpt, not runnable")
