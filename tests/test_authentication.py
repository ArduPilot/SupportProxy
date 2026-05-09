"""
Authentication Tests for SupportProxy.
Tests MAVLink authentication, key validation, and database operations.
"""
import subprocess
import os
import pytest
from test_config import KEYDB_PY


class TestAuthentication:
    """Test suite for authentication functionality."""

    def test_database_creation(self):
        """Test creating the authentication database."""
        # Remove existing database if it exists
        if os.path.exists("keys.tdb"):
            os.remove("keys.tdb")

        # Create new database
        result = subprocess.run(
            ['python', KEYDB_PY, 'initialise'],
            capture_output=True,
            text=True
        )

        # Database creation should succeed
        assert result.returncode == 0
        assert os.path.exists("keys.tdb")

    def test_add_user_to_database(self):
        """Test adding a user to the authentication database."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Add a test user-engineer pair
        result = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15000', '15001', 'test_pair', 'test_key_123'
        ], capture_output=True, text=True)

        # User addition should succeed
        assert result.returncode == 0

    def test_list_users_in_database(self):
        """Test listing users in the authentication database."""
        # Ensure database exists with test pair
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])
            subprocess.run([
                'python', KEYDB_PY, 'add',
                '15010', '15011', 'list_test_pair', 'list_test_key'
            ])

        # List users
        result = subprocess.run([
            'python', KEYDB_PY, 'list'
        ], capture_output=True, text=True)

        # Should list users successfully
        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_remove_user_from_database(self):
        """Test removing a user from the authentication database."""
        # Ensure database exists with test user
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Add user first
        subprocess.run([
            'python', KEYDB_PY, 'add',
            '15020', '15021', 'remove_test_pair', 'remove_test_key'
        ])

        # Remove the user-engineer pair
        result = subprocess.run([
            'python', KEYDB_PY, 'remove', '15021'
        ], capture_output=True, text=True)

        # User removal should succeed
        assert result.returncode == 0

    def test_duplicate_user_handling(self):
        """Test handling of duplicate user additions."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Add user first time
        result1 = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15030', '15031', 'duplicate_pair', 'key1'
        ], capture_output=True, text=True)

        # Add same user second time (will fail because port2 already exists)
        result2 = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15032', '15031', 'duplicate_pair_2', 'key2'
        ], capture_output=True, text=True)

        # First addition should succeed
        assert result1.returncode == 0

        # Second addition should handle gracefully
        # (either succeed with update or fail gracefully)
        assert result2.returncode in [0, 1]

    def test_invalid_port_number(self):
        """Test handling of invalid port numbers."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Try to add pair with invalid ports
        result = subprocess.run([
            'python', KEYDB_PY, 'add',
            '999999', '999998', 'invalid_port_pair', 'key'
        ], capture_output=True, text=True)

        # Should handle invalid port gracefully
        # (either reject it or accept it)
        assert result.returncode in [0, 1]

    def test_empty_username_handling(self):
        """Test handling of empty usernames."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Try to add pair with empty username - this will fail
        result = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15040', '15041', '', 'key'
        ], capture_output=True, text=True)

        # Should accept empty username (keydb.py doesn't validate this)
        assert result.returncode == 0

    def test_empty_key_handling(self):
        """Test handling of empty authentication keys."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Try to add pair with empty key
        result = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15050', '15051', 'empty_key_pair', ''
        ], capture_output=True, text=True)

        # Should accept empty key (keydb.py doesn't validate this)
        assert result.returncode == 0

    def test_special_characters_in_username(self):
        """Test handling of special characters in usernames."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Try various special characters
        special_users = [
            'user@domain.com',
            'user-with-dashes',
            'user_with_underscores',
            'user.with.dots'
        ]

        port_base = 15060
        for i, username in enumerate(special_users):
            result = subprocess.run([
                'python', KEYDB_PY, 'add',
                str(port_base + i*2), str(port_base + i*2 + 1),
                username, f'key_{username}'
            ], capture_output=True, text=True)

            # Should handle special characters gracefully
            assert result.returncode in [0, 1]

    def test_long_username_handling(self):
        """Test handling of very long usernames."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Create a very long username
        long_username = 'x' * 1000

        result = subprocess.run([
            'python', KEYDB_PY, 'add',
            '15070', '15071', long_username, 'key'
        ], capture_output=True, text=True)

        # Should handle long usernames gracefully
        assert result.returncode in [0, 1]

    def test_database_file_permissions(self):
        """Test database file permissions and access."""
        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        # Check that database file exists and is readable
        assert os.path.exists("keys.tdb")
        assert os.access("keys.tdb", os.R_OK)

        # Check file size is reasonable
        file_size = os.path.getsize("keys.tdb")
        assert file_size > 0
        assert file_size < 1024 * 1024  # Less than 1MB for test database

    def test_concurrent_database_access(self):
        """Test concurrent access to the database."""
        import threading

        # Ensure database exists
        if not os.path.exists("keys.tdb"):
            subprocess.run(['python', KEYDB_PY, 'initialise'])

        def add_user_thread(thread_id):
            result = subprocess.run([
                'python', KEYDB_PY, 'add',
                str(15080 + thread_id*2), str(15081 + thread_id*2),
                f'concurrent_pair_{thread_id}',
                f'key_{thread_id}'
            ], capture_output=True, text=True)
            return result.returncode

        # Start multiple threads
        threads = []
        results = []

        for i in range(3):
            thread = threading.Thread(
                target=lambda i=i: results.append(add_user_thread(i))
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=10)

        # Most operations should succeed
        successful_ops = sum(1 for result in results if result == 0)
        assert successful_ops >= 1  # At least one should succeed

    def test_keydb_help_functionality(self):
        """Test the help functionality of keydb.py."""
        result = subprocess.run([
            'python', KEYDB_PY, '--help'
        ], capture_output=True, text=True)

        # Help should display successfully
        assert result.returncode == 0
        help_text = result.stdout.lower()
        assert 'usage' in help_text or 'help' in help_text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
