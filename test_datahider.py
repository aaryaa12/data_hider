import unittest
from datahider import encrypt_message, decrypt_message, generate_key
from cryptography.fernet import Fernet
import base64
import hashlib  # Import hashlib


class TestSteganography(unittest.TestCase):

    def test_encrypt_message(self):
        message = "Hello, this is a test message!"
        password = "strongpassword123"

        # Encrypt the message
        encrypted_message = encrypt_message(message, password)

        # Generate the same key using the password
        key = generate_key(password)
        cipher_suite = Fernet(key)

        # Decrypt the message to verify it matches the original
        decrypted_message = cipher_suite.decrypt(encrypted_message).decode()

        self.assertEqual(message, decrypted_message)

    def test_decrypt_message(self):
        message = "Hello, this is a test message!"
        password = "strongpassword123"

        # Encrypt the message
        encrypted_message = encrypt_message(message, password)

        # Decrypt the message using the decrypt_message function
        decrypted_message = decrypt_message(encrypted_message, password)

        self.assertEqual(message, decrypted_message)

    def test_generate_key(self):
        password = "strongpassword123"
        expected_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

        # Generate the key using the generate_key function
        actual_key = generate_key(password)

        self.assertEqual(expected_key, actual_key)


if __name__ == '__main__':
    unittest.main()
