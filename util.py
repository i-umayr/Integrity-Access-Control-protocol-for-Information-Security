import rsa
from SIH import SIH
import random
import json
import hashlib

def hash(block):
        """
        Create a SHA-256 hash of a block.
        """
        def convert_to_serializable(obj):
            if isinstance(obj, bytes):
                return obj.hex()  # Convert bytes to hexadecimal string
            return obj
        block_string = json.dumps(block, sort_keys=True, default=convert_to_serializable).encode()
        return hashlib.sha256(block_string).hexdigest()

def verify_integrity(data, public_key, encrypted_data, symmetric_key, data_hash=None, signature=None):

    def verify_signature(signature, public_key, data):
        """
        Verify a digital signature using a public key.
        """
        from io import BytesIO

        # Convert the 'data' to a file-like object
        data_file = BytesIO(data.encode('utf-8'))
        try:
            rsa.verify(data_file, signature, public_key)
            return True
        except rsa.VerificationError:
            return False

    """
    Verify integrity of data using digital signature and encrypted hash.
    """
    # Verify digital signature if provided
    if signature is not None:
        if not verify_signature(signature, public_key, data):
            return False, "Digital signature verification failed"
        else:
            print("Digital signature verified successfully \n")

    # Decrypt encrypted data using symmetric key
    sih = SIH(encrypted_data)
    decrypted_data = sih.decrypt_data(encrypted_data, symmetric_key)

    # Calculate hash of the data
    if data_hash is not None:
        sih.data = decrypted_data
        calculated_hash = sih.calculate_hash(symmetric_key)

        # Compare decrypted hash with calculated hash
        if data_hash != calculated_hash:
            return False, "Hash verification failed"
        else:
            print("Hash verified successfully")
            print("Calculated Hash:", calculated_hash)
            print("Data Hash:", data_hash, "\n")

    return True, "Verified"  # Shorter success message

def compromise_blockchain_data_integrity(blockchain, transaction_index, new_data):

    # Extract the transaction to be modified
    transaction = blockchain.chain[transaction_index]['transactions']

    old_data = transaction[0]['data']

    modified_data_hash = transaction[0]['data hash']

    # Extract relevant information from the transaction and convert hexadecimal strings to bytes
    symmetric_key = transaction[0]['symmetric key']

    # Modify the encrypted data
    sih = SIH(new_data)
    modified_encrypted_data = sih.encrypt_data(symmetric_key)

    #Convert symmetric key and public key to hexadecimal strings
    symmetric_key = symmetric_key.hex()

    # Replace the original transaction with the modified one in the blockchain
    modified_transaction = {
        'data': new_data,
        'data hash': modified_data_hash,
        'encrypted data': modified_encrypted_data,
        'symmetric key': symmetric_key,
    }

    # Save the modified transaction
    blockchain.chain[transaction_index]['transactions'][0] = modified_transaction

    # Use the hash of the last block as previous hash
    previous_hash = hash(blockchain.chain[transaction_index])
    blockchain.chain[transaction_index + 1]['previous_hash'] = previous_hash

    #Change the previous hashes of all the blocks after the modified block
    for i in range(transaction_index + 2, len(blockchain.chain)):
        blockchain.chain[i]['previous_hash'] = hash(blockchain.chain[i - 1])

    # Save the modified blockchain
    blockchain.save_chain()

    return old_data, new_data

def generate_random_string(length):
    """
    Generate a random string of specified length.
    """
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choice(charset) for _ in range(length))

def intercept_message(sender, receiver, message):
    # Intercept message from sender to receiver
    print("[MITM] Intercepting message from", sender, "to", receiver)
    print("[MITM] Original message:", message)

    # Modify the message
    modified_message = "Modified message from {} to {}".format(sender, receiver)

    return modified_message