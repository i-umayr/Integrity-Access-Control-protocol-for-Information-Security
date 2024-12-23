import rsa
import os
from SIH import SIH
import random
from blockchain import Blockchain
from util import verify_integrity, compromise_blockchain_data_integrity ,generate_random_string , intercept_message

if __name__ == "__main__":
    # Generate RSA keys
    public_key,private_key = rsa.newkeys(2048)

    # Generate symmetric key
    symmetric_key = os.urandom(32)

    # Data to be secured
    data = str(input("Enter the data to be secured: "))

    # Step 1: Calculate hash of the data
    sih = SIH(data)
    data_hash = sih.calculate_hash(symmetric_key)
    print("Data Hash:", data_hash, "\n")

    # Step 2: Encrypt data using symmetric key
    encrypted_data = sih.encrypt_data(symmetric_key)
    print("Encrypted Data:", encrypted_data, "\n")

    # Step 3: Generate digital signature
    signature = sih.generate_signature(private_key)
    print("Digital Signature:", signature, "\n")

    # Step 6: Blockchain Integration
    blockchain = Blockchain()
    transaction_data = {
        'data': data,
        'data hash': data_hash,
        'encrypted data': encrypted_data,
        'symmetric key': symmetric_key,
    }
    blockchain.new_transaction(transaction_data)
    previous_hash = None if not blockchain.chain else blockchain.hash(blockchain.chain[-1])
    blockchain.new_block(previous_hash)

    # Mine a new block
    if blockchain.chain:
        previous_hash = blockchain.hash(blockchain.chain[-1])
    else:
        previous_hash = "1"

    # Step 7: Verify integrity
    result, message = verify_integrity(data, public_key, encrypted_data, symmetric_key,data_hash, signature )
    print(message, "\n")

print("----------------------------------------------Properties of SIH---------------------------------------------- \n")
print("1. Avalanche Effect: \n")
data1 = "Hello world"
data2 = "Hello World"
sih = SIH(data1)
hash1 = sih.calculate_hash(symmetric_key)
sih.data = data2
hash2 = sih.calculate_hash(symmetric_key)

if hash1 != hash2:
    print("Hash function has high diffusion. Changing one alphabet in the input data changes the hash value significantly.")
    print("Hash1:", hash1)
    print("Hash2:", hash2, "\n")

print("2. Hamming Distance between 2 Hashes having only one alphabet changed (The Larger the Better).")
print(sum(bin(ord(x) ^ ord(y)).count('1') for x, y in zip(hash1, hash2)), "\n")

print("3. Pre-image Resistance:")
print("It is computationally infeasible to find the original data from the hash value. \n")
target_hash = hash1
for _ in range(10000):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
    sih.data = random_data
    random_hash = sih.calculate_hash(symmetric_key)
    if random_hash == target_hash:
        print("Pre-image Resistance property compromised as hash values are same")
        break
print("Pre-image Resistance property is maintained as hash values are different")

print("4. Second Pre-image Resistance:")
print("It is computationally infeasible to find another data with the same hash value as the original data. \n")

sih.data = data1
original_hash = sih.calculate_hash(symmetric_key)
for _ in range(10000):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
    if random_data == data1:
        continue
    sih.data = random_data
    random_hash = sih.calculate_hash(symmetric_key)
    if random_hash == original_hash:
        print("Second Pre-image Resistance property compromised as hash values are same")
        break
print("Second Pre-image Resistance property is maintained as hash values are different")

print("5. Collision Resistance:")
print("It is computationally infeasible to find two different data with the same hash value. \n")

seen_hashes = {}
for _ in range(10000):
    random_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
    sih.data = random_data
    random_hash = sih.calculate_hash(symmetric_key)
    hash_hex = random_hash
    if hash_hex in seen_hashes:
        print(seen_hashes[hash_hex], random_data, "have the same hash value hence Collision Resistance property is compromised")
        break
    seen_hashes[hash_hex] = random_data
print("Collision Resistance property is maintained as hash values are different")

print("-----------------------------------------Attack on Data Integrity----------------------------------------- \n")
print(" `Compromising the integrity of the blockchain by modifying the data in a transaction` \n")
# Define the index of the transaction to be modified
transaction_index = int(input("Enter the index of the transaction to be modified: "))  

# Check if there are transactions in the last block
if blockchain.chain:
    if blockchain.chain[transaction_index]['transactions'] == []:
        print("No transactions in this block. Cannot compromise data integrity. \n")
    else:
        new_data = str(input("Enter the new data to replace the original data on the specified index: "))

        # Perform the attack
        old_data,new_data = compromise_blockchain_data_integrity(blockchain, transaction_index, new_data)

        modified_transaction = blockchain.chain[transaction_index]['transactions']
        result, message = verify_integrity(
            modified_transaction[0]['data'],
            public_key,
            modified_transaction[0]['encrypted data'],
            bytes.fromhex(modified_transaction[0]['symmetric key']),
            # modified_transaction[0]['data hash']
        )
        print(message, "\n Hence the integrity of blockchain is compromised. \n")
        print("Original Data:", old_data)
        print("Modified Data:", new_data)
else:
    print("Blockchain is empty. Cannot compromise data integrity. \n")

print("`Compromising the integrity of messages by deploying (Man in The Middle Attack)` \n")
# Initialize MITM attack assuming the attacker knows the hash function and symmetric key(which he obtained through brute force attack)
# It also assumes the communication is not encrypted and signed

# Alice sends a message to Bob
alice_message = "Hello Bob, this is Alice."
bob_message = intercept_message("Alice", "Bob", alice_message)
# Calculate modified hash
fake_sih = SIH(bob_message)
bob_hash = fake_sih.calculate_hash(symmetric_key)

print("[MITM] Modified message:", bob_message)
print("[MITM] Modified hash:", bob_hash)

# Bob responds to Alice
modified_bob_response = intercept_message("Bob", "Alice", "Hi Alice, I received your message.")
# Calculate modified hash
fake_sih.data = modified_bob_response
modified_bob_hash = fake_sih.calculate_hash(symmetric_key)

print("[MITM] Modified message:", modified_bob_response)
print("[MITM] Modified hash:", modified_bob_hash)

# Alice responds to Bob
modified_alice_response = intercept_message("Alice", "Bob", "Hi Bob, I received your response.")
# Calculate modified hash
fake_sih.data = modified_alice_response
modified_alice_hash = fake_sih.calculate_hash(symmetric_key)

print("[MITM] Modified message:", modified_alice_response)
print("[MITM] Modified hash:", modified_alice_hash)

print("`Compromising the integrity of hash function by generating a collision (Birthday Attack)` \n")
hash_dict = {}
num_attempts = 0
 
while (num_attempts<=10000):
    num_attempts += 1
    random_string = generate_random_string(10)
    fake_sih = SIH(random_string)
    hash_value = fake_sih.calculate_hash(symmetric_key)
 
    if hash_value in hash_dict:
        print(f"Collision found after {num_attempts} attempts!")
        print(f"Original String 1: {hash_dict[hash_value]}")
        print(f"Hash of String 1: {hash_value}")
        print(f"Original String 2: {random_string}")
        print(f"Hash of String 2: {hash_value}")
        break
 
    hash_dict[hash_value] = random_string
print(f"Unsuccessful after {num_attempts} attempts!")