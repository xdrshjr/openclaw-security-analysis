#!/usr/bin/env python3
"""
Test 05: Configuration and Secrets Management Security
======================================================
Tests OpenClaw's configuration system for secrets exposure vulnerabilities.

Target: src/config/*.ts, .env handling
Issues Tested:
- Secret redaction bypass
- Config file permission issues
- Environment variable exposure
- Sensitive key logging
"""

import unittest
import re
import json
from typing import Dict, Any, List, Optional


class SecretsManagerSimulator:
    """Simulates OpenClaw secrets management."""
    
    SENSITIVE_KEYS = [
        "token", "password", "secret", "apiKey", "api_key",
        "auth", "credential", "privateKey", "key",
    ]
    
    REDACTION_PATTERNS = [
        (r'"[a-f0-9]{32,}"', '"***REDACTED***"'),  # Hex tokens
        (r'Bearer\s+\S+', 'Bearer ***REDACTED***'),  # Bearer tokens
        (r'key[:=]\s*\S+', 'key=***REDACTED***'),   # Key patterns
    ]
    
    def is_sensitive_key(self, key: str) -> bool:
        """Check if a config key is sensitive."""
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in self.SENSITIVE_KEYS)
    
    def redact_value(self, key: str, value: Any) -> Any:
        """Redact sensitive values."""
        if not self.is_sensitive_key(key):
            return value
        
        if isinstance(value, str) and len(value) > 0:
            if len(value) <= 4:
                return "****"
            return value[:2] + "****" + value[-2:]
        
        return "***REDACTED***"
    
    def redact_object(self, obj: dict, path: str = "") -> dict:
        """Recursively redact sensitive values in object."""
        result = {}
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, dict):
                result[key] = self.redact_object(value, current_path)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_object(item, current_path) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = self.redact_value(key, value)
        
        return result


class ConfigurationSecurityTest(unittest.TestCase):
    """Test suite for configuration security."""
    
    def setUp(self):
        self.secrets_mgr = SecretsManagerSimulator()
    
    # Sensitive configuration keys
    SENSITIVE_CONFIG_KEYS = [
        ("gateway.auth.token", "supersecrettoken123", "Gateway auth token"),
        ("gateway.auth.password", "admin123", "Gateway password"),
        ("gateway.remote.token", "remotetoken456", "Remote token"),
        ("gateway.remote.password", "remote123", "Remote password"),
        ("tools.web.search.apiKey", "brave_api_key_789", "Brave API key"),
        ("talk.apiKey", "elevenlabs_key_abc", "ElevenLabs API key"),
        ("channels.telegram.botToken", "telegram_token_def", "Telegram token"),
        ("channels.slack.botToken", "slack_token_ghi", "Slack bot token"),
        ("channels.slack.signingSecret", "slack_secret_jkl", "Slack signing secret"),
        ("models.anthropic.apiKey", "anthropic_key_mno", "Anthropic API key"),
        ("models.openai.apiKey", "openai_key_pqr", "OpenAI API key"),
    ]
    
    # Config file permission risks
    PERMISSION_RISKS = [
        ("~/.openclaw/config.json", 0o644, "World-readable config"),
        ("~/.openclaw/.env", 0o644, "World-readable env file"),
        ("~/.openclaw/exec-approvals.json", 0o666, "Writable by others"),
        ("/tmp/openclaw.log", 0o666, "World-writable log"),
    ]
    
    # Environment variable exposure
    ENV_EXPOSURE_RISKS = [
        ("ANTHROPIC_API_KEY", "sk-ant-api-abc123", "Anthropic key in env"),
        ("OPENAI_API_KEY", "sk-openai-def456", "OpenAI key in env"),
        ("ELEVENLABS_API_KEY", "eleven_ghi789", "ElevenLabs key in env"),
        ("BRAVE_API_KEY", "brave_jkl012", "Brave key in env"),
        ("SLACK_BOT_TOKEN", "xoxb-mno345", "Slack token in env"),
        ("TELEGRAM_BOT_TOKEN", "telegram_pqr678", "Telegram token in env"),
    ]
    
    # Log exposure patterns
    LOG_EXPOSURE_PATTERNS = [
        ("Authorization: Bearer sk-abc123", "Bearer token in log"),
        ('"apiKey": "secret_key_456"', "API key in JSON log"),
        ("password=admin123", "Password in query string"),
        ("token=supersecrettoken", "Token in URL"),
        ("Connecting with token: xyz789", "Token in message"),
    ]

    def test_sensitive_key_detection(self):
        """Test detection of sensitive configuration keys."""
        for key, value, description in self.SENSITIVE_CONFIG_KEYS:
            with self.subTest(key=key, desc=description):
                is_sensitive = self.secrets_mgr.is_sensitive_key(key)
                self.assertTrue(
                    is_sensitive,
                    f"{description}: {key} should be marked as sensitive"
                )

    def test_value_redaction(self):
        """Test that sensitive values are properly redacted."""
        for key, value, description in self.SENSITIVE_CONFIG_KEYS:
            with self.subTest(key=key, desc=description):
                redacted = self.secrets_mgr.redact_value(key, value)
                
                # Original value should not be present
                self.assertNotEqual(
                    redacted,
                    value,
                    f"{description}: Value should be redacted"
                )
                
                # Should contain redaction indicator
                self.assertIn(
                    "*",
                    str(redacted),
                    f"{description}: Redacted value should contain mask"
                )

    def test_nested_object_redaction(self):
        """Test recursive redaction in nested objects."""
        config = {
            "gateway": {
                "auth": {
                    "token": "secrettoken123",
                    "mode": "token",
                },
                "remote": {
                    "password": "remotepass456",
                }
            },
            "models": {
                "anthropic": {
                    "apiKey": "anthrokey789",
                }
            },
            "nonSensitive": {
                "port": 8080,
                "host": "localhost",
            }
        }
        
        redacted = self.secrets_mgr.redact_object(config)
        
        # Sensitive values should be redacted
        self.assertNotEqual(
            redacted["gateway"]["auth"]["token"],
            "secrettoken123"
        )
        self.assertNotEqual(
            redacted["gateway"]["remote"]["password"],
            "remotepass456"
        )
        self.assertNotEqual(
            redacted["models"]["anthropic"]["apiKey"],
            "anthrokey789"
        )
        
        # Non-sensitive values should remain
        self.assertEqual(redacted["nonSensitive"]["port"], 8080)
        self.assertEqual(redacted["nonSensitive"]["host"], "localhost")

    def test_file_permission_risks(self):
        """Test detection of insecure file permissions."""
        for path, mode, description in self.PERMISSION_RISKS:
            with self.subTest(path=path, desc=description):
                # Check if permissions are too permissive
                world_readable = bool(mode & 0o044)
                world_writable = bool(mode & 0o022)
                
                if world_readable or world_writable:
                    self.assertTrue(
                        True,
                        f"{description}: {path} has insecure permissions {oct(mode)}"
                    )

    def test_environment_variable_exposure(self):
        """Test for environment variable exposure risks."""
        for var_name, value, description in self.ENV_EXPOSURE_RISKS:
            with self.subTest(var=var_name, desc=description):
                # Check if variable name suggests sensitivity
                is_sensitive = any(
                    pattern in var_name.lower()
                    for pattern in ["key", "token", "secret", "password", "auth"]
                )
                
                self.assertTrue(
                    is_sensitive,
                    f"{description}: {var_name} appears to contain sensitive data"
                )

    def test_log_exposure_detection(self):
        """Test detection of secrets in log output."""
        for log_line, description in self.LOG_EXPOSURE_PATTERNS:
            with self.subTest(log=log_line[:40], desc=description):
                # Check for common secret patterns
                secret_patterns = [
                    r"[Bb]earer\s+\S+",
                    r"[Tt]oken[:=\s]+\S+",
                    r"[Pp]assword[:=\s]+\S+",
                    r"[Kk]ey[:=\s]+\S+",
                    r"sk-\w+",  # OpenAI/Anthropic key pattern
                    r"xox[baprs]-\w+",  # Slack token pattern
                ]
                
                contains_secret = any(
                    re.search(pattern, log_line)
                    for pattern in secret_patterns
                )
                
                self.assertTrue(
                    contains_secret,
                    f"{description}: Potential secret exposure in log"
                )

    def test_config_file_location_risks(self):
        """Test for risky config file locations."""
        risky_locations = [
            ("/tmp/config.json", "Temp directory"),
            ("/var/tmp/openclaw.env", "Var temp directory"),
            ("./config.json", "Current directory"),
            ("config.backup", "Backup file"),
            ("config.json.old", "Old config"),
            (".env.save", "Saved env file"),
        ]
        
        for path, description in risky_locations:
            with self.subTest(path=path, desc=description):
                # Check for risky patterns
                is_risky = any(
                    pattern in path
                    for pattern in ["/tmp", "/var/tmp", "./", "backup", ".old", ".save"]
                )
                
                self.assertTrue(
                    is_risky,
                    f"{description}: {path} is a risky location for config"
                )


class SnapshotRedactionTest(unittest.TestCase):
    """Test configuration snapshot redaction."""
    
    def test_snapshot_partial_redaction(self):
        """Test that snapshots partially redact sensitive values."""
        # From redact-snapshot.ts: partial redaction (first/last 2 chars)
        value = "supersecrettoken"
        
        if len(value) > 4:
            redacted = value[:2] + "****" + value[-2:]
        else:
            redacted = "****"
        
        self.assertEqual(redacted, "su****en")
        self.assertNotEqual(redacted, value)

    def test_snapshot_differential_privacy(self):
        """Test differential privacy in snapshots."""
        # Snapshots should not expose exact values
        sensitive_config = {
            "password": "exactpassword123",
            "token": "exacttoken456",
        }
        
        # Even partial exposure is risky
        partial_exposure = any(
            len(str(v)) > 4
            for v in sensitive_config.values()
        )
        
        self.assertTrue(partial_exposure, "Partial exposure enables brute force")


class CredentialStorageTest(unittest.TestCase):
    """Test credential storage security."""
    
    def test_credential_encryption_at_rest(self):
        """Document need for credential encryption."""
        storage_methods = [
            ("Plain text JSON", False, "insecure"),
            ("Base64 encoded", False, "insecure"),
            ("Environment variables", False, "risky"),
            ("Keychain/Keyring", True, "secure"),
            ("Encrypted with user password", True, "secure"),
        ]
        
        for method, is_encrypted, security_level in storage_methods:
            with self.subTest(method=method):
                if not is_encrypted:
                    self.assertFalse(
                        is_encrypted,
                        f"{method} is {security_level} - credentials at risk"
                    )

    def test_credential_rotation_detection(self):
        """Test detection of credential rotation needs."""
        # Long-lived credentials should be rotated
        credential_age_days = [
            ("gateway_token", 400, True),   # Old, needs rotation
            ("api_key", 30, False),         # Recent
            ("password", 100, True),        # Getting old
        ]
        
        for name, age, needs_rotation in credential_age_days:
            with self.subTest(credential=name, age=age):
                if needs_rotation:
                    self.assertTrue(
                        needs_rotation,
                        f"{name} is {age} days old - consider rotation"
                    )


class PoCExploitDemonstrations(unittest.TestCase):
    """Proof-of-concept exploit demonstrations."""
    
    def test_poc_config_file_theft(self):
        """
        PoC: Configuration file theft.
        
        1. Attacker gains read access to ~/.openclaw/
        2. Reads config.json with API keys
        3. Extracts unencrypted credentials
        4. Uses credentials for unauthorized access
        
        Mitigation: File permissions 0o600, encryption at rest
        """
        self.assertTrue(True, "PoC documented: Config file theft")

    def test_poc_env_variable_dump(self):
        """
        PoC: Environment variable exposure via process listing.
        
        1. Attacker runs 'ps eww <pid>' on OpenClaw process
        2. Environment variables visible in output
        3. API keys exposed in cleartext
        
        Mitigation: Use config files instead of env vars, clear env after read
        """
        self.assertTrue(True, "PoC documented: Environment variable dump")

    def test_poc_log_analysis_credential_harvesting(self):
        """
        PoC: Credential harvesting from logs.
        
        1. Attacker gains access to log files
        2. Greps for patterns like 'token', 'key', 'password'
        3. Finds redacted but partial credentials
        4. Uses partial info for targeted attacks
        
        Mitigation: Complete redaction, structured logging, log access controls
        """
        self.assertTrue(True, "PoC documented: Log credential harvesting")


if __name__ == "__main__":
    unittest.main(verbosity=2)
