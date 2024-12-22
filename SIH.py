from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import zlib
import os
import rsa

class SIH:
    def __init__(self, data):
        self.data = data

    def calculate_hash(self, symmetric_key):
        """
        Calculate hash of the data using custom hash function.
        """
        def generate_hmac(data,key):
            """
            Generate HMAC (Data Authentication Code) using a symmetric key.
            """
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            if isinstance(data, str):
                h.update(data.encode('utf-8'))
            elif isinstance(data, bytes):
                h.update(data)
            else:
                raise TypeError("Data must be either a string or bytes")
            hmac_code = h.finalize()
            return hmac_code
        
        def compress_data(data):
            """
            Compress data using zlib.
            """
            if isinstance(data, str):
                compressed_data = zlib.compress(data.encode('utf-8'))
            elif isinstance(data, bytes):
                compressed_data = zlib.compress(data)
            else:
                raise TypeError("Data must be either a string or bytes")
            return compressed_data
        
        # Define IV as 32 bits of zeroes
        IV = b'\x00' * 32

        # Padding original message to 512-bit blocks
        block_size = 512
        if isinstance(self.data, str):
            padded_data = self.data.encode() + b'\x00' * ((block_size - len(self.data.encode()) % block_size) % block_size)
        elif isinstance(self.data, bytes):
            padded_data = self.data + b'\x00' * ((block_size - len(self.data) % block_size) % block_size)
        else:
            raise TypeError("Data must be either a string or bytes")
        # Calculate number of segments
        num_segments = len(padded_data) // block_size

        # Initialize HMAC key
        key = symmetric_key

        # Iterate through segments
        for i in range(num_segments):
            # Extract current segment
            segment = padded_data[i * block_size: (i + 1) * block_size]

            # Compress the segment
            compressed_segment = compress_data(segment)

            # Generate HMAC of the compressed segment
            hmac_value = generate_hmac(compressed_segment, key)

            # Append HMAC to IV, word to word addition modulo 2^64
            for j in range(0, len(hmac_value), 8):
                word = hmac_value[j:j+8]
                IV_word = IV[j:j+8]
                IV_word = int.from_bytes(IV_word, 'big')
                word = int.from_bytes(word, 'big')
                new_word = (IV_word + word) % (2**64)
                IV = IV[:j] + new_word.to_bytes(8, 'big') + IV[j+8:]

            # Set the appended HMAC to IV, word to word addition as key for next segment
            key = IV

        # Return the final hash value (Hn)
        return IV.hex()
        
    def encrypt_data(self, key):
        """
        Encrypt data using a symmetric key.
        """
        iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self._pad_data(self.data)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def _pad_data(self, data):
        """
        Apply PKCS7 padding to the data.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        block_size = 16  # AES block size is 128 bits (16 bytes)
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        return padded_data
    
    def decrypt_data(self, encrypted_data, key):
        """
        Decrypt data using a symmetric key.
        """
        iv = bytes(encrypted_data[:16])  # Extract IV from the encrypted data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        return self._unpad_data(decrypted_data)

    def _unpad_data(self, data):
        """
        Remove PKCS7 padding from the data.
        """
        padding_length = data[-1]
        unpadded_data = data[:-padding_length]
        return unpadded_data

    def generate_signature(self, private_key):
        """
        Generate a digital signature using a private key.
        """
        if isinstance(self.data, str):
            data_bytes = self.data.encode('utf-8')
        elif isinstance(self.data, bytes):
            data_bytes = self.data
        else:
            raise TypeError("Data must be either a string or bytes")
        signature = rsa.sign(data_bytes, private_key, 'SHA-256')
        return signature