"""
Comprehensive Tests for Authy Compliance Module
================================================

FAANG-grade test suite with:
- Unit tests for all components
- Integration tests for FIPS crypto
- Audit ledger integrity verification
- Policy evaluation tests
- HSM mock testing
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from authy_server.compliance import (
    CryptoConfig,
    FIPSCryptoModule,
    MockHSMClient,
    AWSKMSClient,
    ImmutableAuditLedger,
    PolicyEngine,
    ComplianceManager,
    HSMProvider,
    AuditEvent,
    create_compliance_manager
)


class TestCryptoConfig(unittest.TestCase):
    """Test cryptographic configuration validation."""
    
    def test_default_config_is_fips_valid(self):
        """Default config should be FIPS valid."""
        config = CryptoConfig()
        self.assertTrue(config.fips_mode)
        self.assertEqual(config.algorithm, "AES-256-GCM")
        self.assertEqual(config.key_size, 256)
        self.assertTrue(config.validate_fips())
    
    def test_invalid_algorithm_raises_error(self):
        """Non-FIPS algorithm should raise error."""
        config = CryptoConfig(algorithm="DES-CBC")
        with self.assertRaises(ValueError):
            config.validate_fips()
    
    def test_invalid_key_size_raises_error(self):
        """Invalid key size should raise error."""
        config = CryptoConfig(key_size=64)
        with self.assertRaises(ValueError):
            config.validate_fips()
    
    def test_low_pbkdf2_iterations_raises_error(self):
        """Low PBKDF2 iterations should raise error."""
        config = CryptoConfig(pbkdf2_iterations=1000)
        with self.assertRaises(ValueError):
            config.validate_fips()
    
    def test_fips_disabled_skips_validation(self):
        """FIPS disabled should skip validation."""
        config = CryptoConfig(fips_mode=False, algorithm="DES-CBC")
        self.assertTrue(config.validate_fips())


class TestFIPSCryptoModule(unittest.TestCase):
    """Test FIPS cryptographic module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = CryptoConfig()
        self.crypto = FIPSCryptoModule(self.config)
    
    def test_module_initializes_successfully(self):
        """Module should initialize and pass self-tests."""
        self.assertTrue(self.crypto.is_fips_compliant())
    
    def test_generate_key_returns_correct_size(self):
        """Generated keys should have correct size."""
        key_128 = self.crypto.generate_key(128)
        key_192 = self.crypto.generate_key(192)
        key_256 = self.crypto.generate_key(256)
        
        self.assertEqual(len(key_128), 16)
        self.assertEqual(len(key_192), 24)
        self.assertEqual(len(key_256), 32)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Encryption/decryption should preserve data."""
        plaintext = b"Secret message for encryption test"
        key = self.crypto.generate_key(256)
        
        ciphertext, nonce = self.crypto.encrypt(plaintext, key)
        decrypted = self.crypto.decrypt(ciphertext, key, nonce)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_with_associated_data(self):
        """AEAD should include associated data."""
        plaintext = b"Confidential data"
        aad = b"metadata:important"
        key = self.crypto.generate_key(256)
        
        ciphertext, nonce = self.crypto.encrypt(plaintext, key, aad)
        decrypted = self.crypto.decrypt(ciphertext, key, nonce, aad)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_decrypt_with_wrong_aad_fails(self):
        """Decryption with wrong AAD should fail."""
        plaintext = b"Confidential data"
        key = self.crypto.generate_key(256)
        
        ciphertext, nonce = self.crypto.encrypt(plaintext, key, b"correct_aad")
        
        with self.assertRaises(Exception):
            self.crypto.decrypt(ciphertext, key, nonce, b"wrong_aad")
    
    def test_hash_deterministic(self):
        """Hash function should be deterministic."""
        data = b"test data for hashing"
        hash1 = self.crypto.hash_data(data)
        hash2 = self.crypto.hash_data(data)
        
        self.assertEqual(hash1, hash2)
    
    def test_hash_different_inputs(self):
        """Different inputs should produce different hashes."""
        hash1 = self.crypto.hash_data(b"data1")
        hash2 = self.crypto.hash_data(b"data2")
        
        self.assertNotEqual(hash1, hash2)
    
    def test_derive_key_deterministic(self):
        """Key derivation should be deterministic."""
        password = "secure_password"
        salt = b"random_salt_here"
        
        key1 = self.crypto.derive_key(password, salt, 100000, 32)
        key2 = self.crypto.derive_key(password, salt, 100000, 32)
        
        self.assertEqual(key1, key2)
    
    def test_derive_key_different_salts(self):
        """Different salts should produce different keys."""
        password = "secure_password"
        
        key1 = self.crypto.derive_key(password, b"salt1", 100000, 32)
        key2 = self.crypto.derive_key(password, b"salt2", 100000, 32)
        
        self.assertNotEqual(key1, key2)


class TestMockHSMClient(unittest.TestCase):
    """Test mock HSM client."""
    
    def setUp(self):
        """Set up HSM client."""
        self.hsm = MockHSMClient()
        self.hsm.connect()
    
    def test_connect_successful(self):
        """Connection should succeed."""
        self.assertTrue(self.hsm._connected)
    
    def test_generate_key_returns_id(self):
        """Key generation should return ID."""
        key_id = self.hsm.generate_key("test-key", "AES-256", 256)
        self.assertTrue(key_id.startswith("hsm-key-"))
    
    def test_get_public_key_returns_data(self):
        """Should retrieve public key."""
        key_id = self.hsm.generate_key("test-key", "RSA-2048", 2048)
        public_key = self.hsm.get_public_key(key_id)
        self.assertIsInstance(public_key, bytes)
        self.assertGreater(len(public_key), 0)
    
    def test_sign_with_key_returns_signature(self):
        """Signing should return signature."""
        key_id = self.hsm.generate_key("signing-key", "RSA-2048", 2048)
        data = b"data to sign"
        signature = self.hsm.sign_with_key(key_id, data)
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 32)  # SHA-256 output
    
    def test_delete_key_removes_from_store(self):
        """Deleted keys should not be retrievable."""
        key_id = self.hsm.generate_key("temp-key", "AES-256", 256)
        self.hsm.delete_key(key_id)
        
        metadata = self.hsm.get_key_metadata(key_id)
        self.assertIsNone(metadata)
    
    def test_get_key_metadata_returns_info(self):
        """Metadata should contain key information."""
        key_id = self.hsm.generate_key("metadata-test", "AES-256", 256)
        metadata = self.hsm.get_key_metadata(key_id)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.key_id, key_id)
        self.assertEqual(metadata.key_type, "AES-256")
        self.assertEqual(metadata.key_size, 256)


class TestImmutableAuditLedger(unittest.TestCase):
    """Test immutable audit ledger."""
    
    def setUp(self):
        """Set up audit ledger."""
        self.temp_dir = tempfile.mkdtemp()
        self.crypto = FIPSCryptoModule()
        self.ledger = ImmutableAuditLedger(
            crypto_module=self.crypto,
            storage_path=self.temp_dir
        )
    
    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_add_entry_creates_record(self):
        """Adding entry should create record."""
        entry = self.ledger.add_entry(
            event_type="login",
            actor_id="user123",
            actor_type="user",
            action="authenticate",
            resource_type="session",
            resource_id="sess_456",
            details={"ip": "192.168.1.1"},
            source_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            tenant_id="tenant1"
        )
        
        self.assertIsNotNone(entry.event_id)
        self.assertTrue(entry.event_id.startswith("evt_"))
        self.assertIsNotNone(entry.current_hash)
    
    def test_hash_chain_integrity(self):
        """Hash chain should maintain integrity."""
        # Add multiple entries
        for i in range(5):
            self.ledger.add_entry(
                event_type="test",
                actor_id=f"user{i}",
                actor_type="user",
                action="test_action",
                resource_type="resource",
                resource_id=f"res{i}",
                details={"index": i},
                source_ip="127.0.0.1",
                user_agent="test",
                tenant_id="default"
            )
        
        # Verify integrity
        is_valid, message = self.ledger.verify_integrity()
        self.assertTrue(is_valid, message)
    
    def test_query_entries_with_filters(self):
        """Should filter entries correctly."""
        # Add entries with different tenants
        self.ledger.add_entry(
            event_type="login",
            actor_id="user1",
            actor_type="user",
            action="login",
            resource_type="session",
            resource_id="s1",
            details={},
            source_ip="1.1.1.1",
            user_agent="test",
            tenant_id="tenant_a"
        )
        
        self.ledger.add_entry(
            event_type="login",
            actor_id="user2",
            actor_type="user",
            action="login",
            resource_type="session",
            resource_id="s2",
            details={},
            source_ip="2.2.2.2",
            user_agent="test",
            tenant_id="tenant_b"
        )
        
        # Query by tenant
        entries = self.ledger.get_entries(tenant_id="tenant_a", limit=10)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].tenant_id, "tenant_a")
    
    def test_export_for_audit(self):
        """Export should create valid JSON file."""
        # Add some entries
        for i in range(3):
            self.ledger.add_entry(
                event_type="test",
                actor_id=f"user{i}",
                actor_type="user",
                action="test",
                resource_type="test",
                resource_id=f"r{i}",
                details={},
                source_ip="127.0.0.1",
                user_agent="test",
                tenant_id="default"
            )
        
        export_path = os.path.join(self.temp_dir, "export.json")
        result_path = self.ledger.export_for_audit(export_path)
        
        self.assertTrue(os.path.exists(result_path))
        
        with open(result_path, 'r') as f:
            export_data = json.load(f)
        
        self.assertEqual(export_data["entry_count"], 3)
        self.assertIn("merkle_root", export_data)
        self.assertIn("entries", export_data)


class TestPolicyEngine(unittest.TestCase):
    """Test policy engine."""
    
    def setUp(self):
        """Set up policy engine."""
        self.temp_dir = tempfile.mkdtemp()
        self.engine = PolicyEngine(policies_dir=self.temp_dir)
        self.engine.create_default_policies()
    
    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_admin_policy_allows_admin_actions(self):
        """Admin policy should allow admin actions."""
        allowed, context = self.engine.evaluate(
            "admin_access",
            {"role": "admin", "action": "read"}
        )
        self.assertTrue(allowed)
    
    def test_admin_policy_denies_non_admin(self):
        """Admin policy should deny non-admin users."""
        allowed, context = self.engine.evaluate(
            "admin_access",
            {"role": "user", "action": "read"}
        )
        self.assertFalse(allowed)
    
    def test_user_self_service_allows_own_data(self):
        """User policy should allow accessing own data."""
        allowed, context = self.engine.evaluate(
            "user_self_service",
            {
                "role": "user",
                "action": "read",
                "resource_owner": "user123",
                "user_id": "user123"
            }
        )
        self.assertTrue(allowed)
    
    def test_user_self_service_denies_others_data(self):
        """User policy should deny accessing others' data."""
        allowed, context = self.engine.evaluate(
            "user_self_service",
            {
                "role": "user",
                "action": "read",
                "resource_owner": "user456",
                "user_id": "user123"
            }
        )
        self.assertFalse(allowed)
    
    def test_mfa_enforcement_requires_mfa_for_sensitive(self):
        """MFA policy should require MFA for sensitive actions."""
        allowed, context = self.engine.evaluate(
            "mfa_enforcement",
            {
                "mfa_verified": False,
                "action": "delete_account"
            }
        )
        self.assertFalse(allowed)
    
    def test_mfa_enforcement_allows_with_mfa(self):
        """MFA policy should allow with verified MFA."""
        allowed, context = self.engine.evaluate(
            "mfa_enforcement",
            {
                "mfa_verified": True,
                "action": "delete_account"
            }
        )
        self.assertTrue(allowed)
    
    def test_register_custom_policy(self):
        """Should register custom policies."""
        custom_policy = """package custom

default allow := false

allow {
    input.department == "engineering"
    input.resource_type == "code_repository"
}
"""
        self.engine.register_policy("engineering_access", custom_policy)
        
        allowed, context = self.engine.evaluate(
            "engineering_access",
            {"department": "engineering", "resource_type": "code_repository"}
        )
        self.assertTrue(allowed)
    
    def test_get_policy_report(self):
        """Policy report should contain all policies."""
        report = self.engine.get_policy_report()
        
        self.assertEqual(report["total_policies"], 5)
        self.assertIn("admin_access", report["policies"])
        self.assertIn("user_self_service", report["policies"])


class TestComplianceManager(unittest.TestCase):
    """Test compliance manager integration."""
    
    def setUp(self):
        """Set up compliance manager."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ComplianceManager(
            audit_storage_path=os.path.join(self.temp_dir, "audit"),
            policies_dir=os.path.join(self.temp_dir, "policies")
        )
    
    def tearDown(self):
        """Clean up temp directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization_successful(self):
        """Manager should initialize all components."""
        self.assertTrue(self.manager.crypto_module.is_fips_compliant())
        self.assertIsNotNone(self.manager.audit_ledger)
        self.assertIsNotNone(self.manager.policy_engine)
    
    def test_record_audit_event(self):
        """Should record audit events."""
        event = self.manager.record_audit_event(
            event_type="user_login",
            actor_id="user123",
            action="authenticate",
            resource_type="session",
            resource_id="sess_456",
            details={"success": True},
            source_ip="192.168.1.100",
            user_agent="TestClient/1.0",
            tenant_id="acme-corp"
        )
        
        self.assertIsNotNone(event.event_id)
        self.assertEqual(event.actor_id, "user123")
    
    def test_check_policy_integration(self):
        """Policy checking should work through manager."""
        allowed, context = self.manager.check_policy(
            "admin_access",
            {"role": "admin", "action": "write"}
        )
        self.assertTrue(allowed)
    
    def test_generate_compliance_report(self):
        """Compliance report should be comprehensive."""
        # Record some events first
        self.manager.record_audit_event(
            event_type="test",
            actor_id="system",
            action="test",
            resource_type="test",
            resource_id="test",
            details={},
            tenant_id="default"
        )
        
        report = self.manager.generate_compliance_report()
        
        self.assertEqual(report["compliance_status"], "COMPLIANT")
        self.assertTrue(report["fips_140_2"]["validated"])
        self.assertTrue(report["audit_ledger"]["integrity_verified"])
        self.assertIn("SOC2", report["standards"])
        self.assertIn("HIPAA", report["standards"])
        self.assertIn("FedRAMP", report["standards"])
    
    def test_rotate_keys(self):
        """Key rotation should create new key and log event."""
        # Generate initial key
        initial_key = self.manager.hsm_client.generate_key(
            "initial-key", "AES-256", 256
        )
        
        # Rotate key
        new_key = self.manager.rotate_keys(initial_key)
        
        self.assertNotEqual(initial_key, new_key)
        self.assertTrue(new_key.startswith("hsm-key-"))
        
        # Verify rotation was logged
        entries = self.manager.audit_ledger.get_entries(
            event_type="key_rotation",
            limit=10
        )
        self.assertGreater(len(entries), 0)


class TestCreateComplianceManager(unittest.TestCase):
    """Test convenience factory function."""
    
    def test_create_with_defaults(self):
        """Should create manager with default settings."""
        manager = create_compliance_manager()
        
        self.assertTrue(manager.crypto_module.is_fips_compliant())
        self.assertEqual(manager.hsm_provider, HSMProvider.MOCK)
    
    def test_create_with_custom_settings(self):
        """Should create manager with custom settings."""
        manager = create_compliance_manager(
            fips_mode=True,
            hsm_provider="mock",
            audit_path="/tmp/test_audit"
        )
        
        self.assertTrue(manager.crypto_module.is_fips_compliant())


def run_tests():
    """Run all tests and print results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestFIPSCryptoModule))
    suite.addTests(loader.loadTestsFromTestCase(TestMockHSMClient))
    suite.addTests(loader.loadTestsFromTestCase(TestImmutableAuditLedger))
    suite.addTests(loader.loadTestsFromTestCase(TestPolicyEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestComplianceManager))
    suite.addTests(loader.loadTestsFromTestCase(TestCreateComplianceManager))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
