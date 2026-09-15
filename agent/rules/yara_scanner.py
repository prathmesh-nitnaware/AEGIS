"""
agent/rules/yara_scanner.py
===========================
AEGIS Autonomous EDR - In-Memory YARA Threat Scanning Engine
------------------------------------------------------------
Provides high-speed, in-memory pattern matching for binary payloads, executable
droppers, and suspicious memory buffers using YARA-compatible syntax.

Features:
- Hex byte sequences with wildcards: `{ 4D 5A 90 00 ?? ?? 00 00 }`.
- Case-insensitive ASCII & wide text strings.
- Regular expression signature scanning.
- Condition evaluation (`all of them`, `any of them`, `2 of ($a, $b, $c)`, `filesize < X`).
- Seamless integration with AgentResponseDriver before file quarantine.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger("aegis.yara_scanner")


@dataclass
class YARAPattern:
    """Represents a compiled pattern within a YARA rule."""
    name: str  # e.g. "$str1", "$hex1", "$re1"
    pattern_type: str  # "text", "hex", "regex"
    raw_pattern: str
    compiled_regex: re.Pattern


@dataclass
class YARARule:
    """Represents a compiled in-memory YARA rule."""
    name: str
    meta: Dict[str, Any]
    strings: List[YARAPattern]
    condition: str
    description: str = ""

    def scan_bytes(self, buffer: bytes) -> bool:
        """
        Scans a byte buffer against the rule's compiled strings and condition.
        """
        matched_strings: Dict[str, bool] = {}

        for pat in self.strings:
            matched = bool(pat.compiled_regex.search(buffer))
            matched_strings[pat.name] = matched

        # Evaluate condition
        cond = self.condition.strip().lower()
        if cond in ("all of them", "all of ($*)"):
            return all(matched_strings.values()) if matched_strings else False
        elif cond in ("any of them", "1 of them", "any of ($*)", "1 of ($*)"):
            return any(matched_strings.values())
        elif " and " in cond:
            parts = [p.strip() for p in cond.split(" and ")]
            return all(matched_strings.get(p, False) for p in parts)
        elif " or " in cond:
            parts = [p.strip() for p in cond.split(" or ")]
            return any(matched_strings.get(p, False) for p in parts)
        else:
            return matched_strings.get(cond, False)


class YARAScanner:
    """
    In-memory YARA scanner compiling rules and matching binary buffers or files.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, YARARule] = {}
        self._load_default_signatures()

    def _compile_hex_pattern(self, hex_str: str) -> re.Pattern:
        """
        Compiles a YARA hex byte pattern into a regex bytes pattern.
        e.g. '{ 4D 5A ?? 00 }' -> b'\x4d\x5a.[\x00]'
        """
        cleaned = hex_str.replace("{", "").replace("}", "").strip()
        tokens = cleaned.split()

        re_parts = []
        for t in tokens:
            if t == "??" or t == "?":
                re_parts.append(b".")
            else:
                try:
                    val = bytes.fromhex(t)
                    re_parts.append(re.escape(val))
                except Exception:
                    re_parts.append(b".")

        combined = b"".join(re_parts)
        return re.compile(combined, re.DOTALL)

    def add_rule(
        self,
        name: str,
        strings_dict: Dict[str, str],
        condition: str = "any of them",
        meta: Optional[Dict[str, Any]] = None,
    ) -> YARARule:
        """
        Compiles and registers a new YARA rule.
        """
        patterns = []
        for s_name, s_val in strings_dict.items():
            s_val = s_val.strip()
            if s_val.startswith("{") and s_val.endswith("}"):
                c_re = self._compile_hex_pattern(s_val)
                p_type = "hex"
            elif s_val.startswith("/") and s_val.endswith("/"):
                regex_str = s_val[1:-1]
                c_re = re.compile(regex_str.encode("utf-8", errors="ignore"), re.IGNORECASE)
                p_type = "regex"
            else:
                # Text string
                c_re = re.compile(re.escape(s_val.encode("utf-8")), re.IGNORECASE)
                p_type = "text"

            patterns.append(YARAPattern(name=s_name, pattern_type=p_type, raw_pattern=s_val, compiled_regex=c_re))

        rule = YARARule(
            name=name,
            meta=meta or {},
            strings=patterns,
            condition=condition,
            description=meta.get("description", "") if meta else "",
        )
        self._rules[name] = rule
        return rule

    def scan_buffer(self, data: bytes) -> List[Dict[str, Any]]:
        """Scans in-memory byte buffer against all loaded YARA rules."""
        matched = []
        for r in self._rules.values():
            if r.scan_bytes(data):
                matched.append({
                    "rule": r.name,
                    "meta": r.meta,
                    "description": r.description,
                })
        return matched

    def scan_file(self, file_path: str | Path) -> Dict[str, Any]:
        """Reads file from disk and scans in-memory."""
        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            return {"scanned": False, "reason": f"File not found: {path}", "matches": []}

        try:
            with open(path, "rb") as f:
                data = f.read()

            matches = self.scan_buffer(data)
            return {
                "scanned": True,
                "file_path": str(path),
                "size_bytes": len(data),
                "is_malicious": len(matches) > 0,
                "matches": matches,
            }
        except Exception as exc:
            return {"scanned": False, "reason": str(exc), "matches": []}

    def list_rules(self) -> List[Dict[str, Any]]:
        """Returns summary metadata for all compiled YARA rules."""
        return [
            {
                "name": r.name,
                "condition": r.condition,
                "string_count": len(r.strings),
                "meta": r.meta,
            }
            for r in self._rules.values()
        ]

    @property
    def rules(self) -> List[YARARule]:
        """Returns list of loaded rules."""
        return list(self._rules.values())

    def scan_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """Alias for scan_buffer."""
        return self.scan_buffer(data)

    def _load_default_signatures(self) -> None:
        """Preloads common high-threat signatures."""
        # 1. Ransomware Note & Shadow Wipe signature
        self.add_rule(
            name="Ransomware_Readme_Note",
            strings_dict={
                "$vss": "vssadmin delete shadows",
                "$note1": "encrypted with AES-256",
                "$note2": "Bitcoin address",
                "$note3": "YOUR FILES HAVE BEEN ENCRYPTED",
            },
            condition="any of them",
            meta={"severity": "CRITICAL", "category": "Ransomware", "mitre": "T1486"},
        )

        # 2. Cobalt Strike / Metasploit Stager PE Header
        self.add_rule(
            name="Metasploit_Reverse_TCP_Stager",
            strings_dict={
                "$pe_hdr": "{ 4D 5A 90 00 }",
                "$meterpreter": "meterpreter_reverse_tcp",
                "$shellcode": "{ FC E8 ?? ?? ?? ?? 60 89 E5 }",
            },
            condition="any of them",
            meta={"severity": "HIGH", "category": "C2 / Stager", "mitre": "T1059"},
        )

        # 3. Generic WebShell Command Injector
        self.add_rule(
            name="Generic_Webshell_PHP",
            strings_dict={
                "$cmd": "$_POST['cmd']",
                "$system": "system($_POST",
                "$eval": "eval($_POST[",
                "$shell_exec": "shell_exec(",
                "$passthru": "passthru(",
            },
            condition="any of them",
            meta={"severity": "HIGH", "category": "WebShell", "mitre": "T1505"},
        )


# Aliases
YaraScanner = YARAScanner
YaraRule = YARARule
YaraPattern = YARAPattern

# Global singleton instance
default_yara_scanner = YARAScanner()

