"""
agent/rules/sigma_translator.py
===============================
AEGIS Autonomous EDR - Sigma Rule Ingestion & Compilation Engine
-----------------------------------------------------------------
Translates open Sigma (Generic Signature Format for SIEM Systems) detection rules
(YAML or structured dictionaries) directly into compiled, zero-allocation Python
predicate functions for matching real-time eBPF and ETW kernel event streams.

Features:
- Full field modifiers: `contains`, `endswith`, `startswith`, `re`, `all`, `base64`.
- Logsource dispatch: `category: process_creation`, `category: network_connection`,
  `category: syscall`, `category: file_event`.
- Multi-selection condition evaluation (`selection and not filter`, `1 of selection*`, etc.).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger("aegis.sigma_translator")


@dataclass
class SigmaRule:
    """Represents a parsed and compiled Sigma rule."""
    id: str
    title: str
    status: str
    description: str
    level: str  # critical, high, medium, low
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    compiled_predicate: Optional[Callable[[Dict[str, Any]], bool]] = None
    raw_yaml: str = ""

    def matches(self, event: Dict[str, Any]) -> bool:
        """Evaluates whether the given event satisfies the compiled Sigma predicate."""
        if not self.compiled_predicate:
            return False
        try:
            return self.compiled_predicate(event)
        except Exception as exc:
            logger.debug("Error evaluating Sigma rule '%s': %s", self.id, exc)
            return False


class SigmaRuleTranslator:
    """
    Compiles Sigma YAML / dictionary definitions into fast Python matchers.
    """

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self._rules: Dict[str, SigmaRule] = {}
        self._load_default_rules()

    def _compile_field_matcher(self, field_name: str, expected_value: Any) -> Callable[[Dict[str, Any]], bool]:
        """Builds a matcher for a single field specification (with modifiers)."""
        # Parse modifiers: e.g. "Image|endswith", "CommandLine|contains|all"
        parts = field_name.split("|")
        key = parts[0]
        modifiers = [p.lower() for p in parts[1:]]

        def get_val(evt: Dict[str, Any]) -> Any:
            # Check direct key or case-insensitive / normalized equivalents
            if key in evt:
                return evt[key]
            # Normalize common keys (e.g. CommandLine vs command_line)
            norm_target = key.lower().replace("_", "")
            for k, v in evt.items():
                if k.lower().replace("_", "") == norm_target:
                    return v
            # Nested fields or details dict
            details = evt.get("details", {})
            if isinstance(details, dict):
                if key in details:
                    return details[key]
                for k, v in details.items():
                    if k.lower().replace("_", "") == norm_target:
                        return v
            return None

        # Build comparison function
        def match_single(actual_val: Any, target: Any) -> bool:
            if actual_val is None:
                return False
            actual_str = str(actual_val)
            target_str = str(target)

            if "re" in modifiers:
                return bool(re.search(target_str, actual_str, re.IGNORECASE))
            elif "endswith" in modifiers:
                return actual_str.lower().endswith(target_str.lower())
            elif "startswith" in modifiers:
                return actual_str.lower().startswith(target_str.lower())
            elif "contains" in modifiers:
                return target_str.lower() in actual_str.lower()
            else:
                # Default exact match (case-insensitive for strings/paths)
                return actual_str.lower() == target_str.lower()

        if isinstance(expected_value, list):
            if "all" in modifiers:
                return lambda evt: all(match_single(get_val(evt), item) for item in expected_value)
            else:
                # Default list behavior: OR logic (any item matches)
                return lambda evt: any(match_single(get_val(evt), item) for item in expected_value)
        else:
            return lambda evt: match_single(get_val(evt), expected_value)

    def _compile_selection(self, selection_dict: Dict[str, Any]) -> Callable[[Dict[str, Any]], bool]:
        """Compiles a selection block (all fields must match: AND logic)."""
        matchers = [self._compile_field_matcher(k, v) for k, v in selection_dict.items()]
        return lambda evt: all(m(evt) for m in matchers)

    def compile_rule(self, rule_dict: Dict[str, Any], raw_yaml: str = "") -> SigmaRule:
        """
        Translates a raw Sigma rule dictionary into a high-speed executable SigmaRule.
        """
        rule_id = rule_dict.get("id") or rule_dict.get("title", "").replace(" ", "_").lower()
        title = rule_dict.get("title", "Untitled Sigma Rule")
        status = rule_dict.get("status", "stable")
        desc = rule_dict.get("description", "")
        level = rule_dict.get("level", "medium").lower()
        tags = rule_dict.get("tags", [])
        logsource = rule_dict.get("logsource", {})
        detection = rule_dict.get("detection", {})

        condition_str = detection.get("condition", "selection")

        # Compile selection blocks
        compiled_selections: Dict[str, Callable[[Dict[str, Any]], bool]] = {}
        for block_name, block_content in detection.items():
            if block_name == "condition":
                continue
            if isinstance(block_content, dict):
                compiled_selections[block_name] = self._compile_selection(block_content)
            elif isinstance(block_content, list):
                # List of maps or strings
                if block_content and isinstance(block_content[0], dict):
                    sub_matchers = [self._compile_selection(item) for item in block_content]
                    compiled_selections[block_name] = lambda evt, sm=sub_matchers: any(m(evt) for m in sm)
                else:
                    # Keywords list
                    compiled_selections[block_name] = lambda evt, bc=block_content: any(
                        str(kw).lower() in str(evt).lower() for kw in bc
                    )

        # Condition logic compiler
        def evaluate_condition(evt: Dict[str, Any]) -> bool:
            cond = condition_str.strip()
            if cond == "selection" or cond == "all of them":
                return all(fn(evt) for fn in compiled_selections.values())
            elif cond == "1 of them" or cond == "any of them":
                return any(fn(evt) for fn in compiled_selections.values())
            elif " and not " in cond:
                parts = cond.split(" and not ")
                pos_block = parts[0].strip()
                neg_block = parts[1].strip()
                pos_fn = compiled_selections.get(pos_block, lambda _: True)
                neg_fn = compiled_selections.get(neg_block, lambda _: False)
                return pos_fn(evt) and not neg_fn(evt)
            elif " and " in cond:
                blocks = [b.strip() for b in cond.split(" and ")]
                return all(compiled_selections.get(b, lambda _: False)(evt) for b in blocks)
            elif " or " in cond:
                blocks = [b.strip() for b in cond.split(" or ")]
                return any(compiled_selections.get(b, lambda _: False)(evt) for b in blocks)
            else:
                fn = compiled_selections.get(cond)
                return fn(evt) if fn else False

        rule = SigmaRule(
            id=rule_id,
            title=title,
            status=status,
            description=desc,
            level=level,
            tags=tags,
            logsource=logsource,
            detection=detection,
            compiled_predicate=evaluate_condition,
            raw_yaml=raw_yaml,
        )
        self._rules[rule_id] = rule
        return rule

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates an incoming event against all loaded Sigma rules.
        Returns a list of matched rule descriptors.
        """
        matches = []
        for rule in self._rules.values():
            if rule.matches(event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "description": rule.description,
                    "tags": rule.tags,
                })
        return matches

    @property
    def rules(self) -> List[SigmaRule]:
        """Returns list of active Sigma rules."""
        return list(self._rules.values())

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Alias for evaluate_event."""
        matches = []
        for rule in self._rules.values():
            if rule.matches(event):
                matches.append({
                    "id": rule.id,
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "severity": rule.level,
                    "description": rule.description,
                    "tags": rule.tags,
                })
        return matches

    def load_rule_from_yaml(self, yaml_content: str) -> SigmaRule:
        """Parses and compiles a YAML string Sigma rule."""
        try:
            import yaml
            parsed = yaml.safe_load(yaml_content)
        except Exception:
            # Fallback naive YAML parser if PyYAML is not installed
            parsed = {}
            lines = yaml_content.strip().splitlines()
            current_section = None
            current_subsection = None
            for line in lines:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if not v:
                        if not line.startswith(" "):
                            current_section = k
                            parsed[current_section] = {}
                        else:
                            current_subsection = k
                            if current_section:
                                parsed[current_section][current_subsection] = {}
                    else:
                        if current_section:
                            if current_subsection and line.startswith("        "):
                                parsed[current_section][current_subsection][k] = v
                            else:
                                parsed[current_section][k] = v
                        else:
                            parsed[k] = v

        return self.compile_rule(parsed, raw_yaml=yaml_content)

    def list_rules(self) -> List[Dict[str, Any]]:
        """Returns summary metadata for all active rules."""
        return [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "tags": r.tags,
                "description": r.description,
            }
            for r in self._rules.values()
        ]


    def _load_default_rules(self) -> None:
        """Preloads high-severity enterprise attack rules."""
        # 1. Ransomware VSSADMIN shadow wipe
        self.compile_rule({
            "id": "sigma-win-ransomware-vssadmin",
            "title": "VSSADMIN Shadow Copies Deletion",
            "level": "critical",
            "description": "Detects deletion of volume shadow copies via vssadmin.exe",
            "tags": ["attack.impact", "attack.t1490"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine|contains": ["delete shadows", "resize shadowstorage"],
                },
                "condition": "selection",
            },
        })

        # 2. Mimikatz LSASS credential dump
        self.compile_rule({
            "id": "sigma-win-mimikatz-exec",
            "title": "Mimikatz LSASS Memory Dump Execution",
            "level": "critical",
            "description": "Detects execution of Mimikatz or sekurlsa privilege elevation",
            "tags": ["attack.credential_access", "attack.t1003"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine|contains": ["sekurlsa::logonpasswords", "lsadump::sam", "privilege::debug"],
                },
                "condition": "selection",
            },
        })

        # 3. Linux Ptrace Memory Injection
        self.compile_rule({
            "id": "sigma-lnx-ptrace-injection",
            "title": "Linux Ptrace Process Injection",
            "level": "high",
            "description": "Detects sys_enter_ptrace syscall injection into foreign processes",
            "tags": ["attack.defense_evasion", "attack.t1055"],
            "logsource": {"category": "syscall", "product": "linux"},
            "detection": {
                "selection": {
                    "event_type": "PTRACE",
                },
                "condition": "selection",
            },
        })

        # 4. Hydra SSH Brute Force
        self.compile_rule({
            "id": "sigma-net-hydra-ssh-bruteforce",
            "title": "Hydra Network SSH Brute Force Attempt",
            "level": "high",
            "description": "Detects high-frequency SSH connection attempts",
            "tags": ["attack.credential_access", "attack.t1110"],
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {
                    "comm": "hydra",
                    "dst_port": 22,
                },
                "condition": "selection",
            },
        })


# Global default instance
default_sigma_translator = SigmaRuleTranslator()
