# Secure Information Handling (SIH) with Blockchain

## Overview

This project demonstrates the implementation of Secure Information Handling (SIH) techniques coupled with a Blockchain framework for ensuring data integrity and security in decentralized systems. SIH employs custom cryptographic hashing, encryption, digital signatures, and authentication mechanisms to protect sensitive data. The Blockchain is utilized as a tamper-resistant ledger for recording and verifying transactions.

## Features

- **Custom Hash Function (SIH)**:
  - Implements a custom hash function based on HMAC-SHA256 for generating data hashes.
  - Provides features like compression and HMAC generation for enhanced security.
  - Ensures properties like avalanche effect, pre-image resistance, and collision resistance.

- **Blockchain Implementation**:
  - Utilizes a decentralized Blockchain data structure for maintaining a secure, append-only ledger.
  - Implements blocks containing transactions, each validated by previous block hashes.
  - Features transaction integrity verification through cryptographic signatures and data hashes.

- **Encryption and Digital Signatures**:
  - Employs RSA encryption for securing data transmission and storage.
  - Generates and verifies digital signatures to ensure data authenticity and integrity.

## Components

### SIH Module (`SIH.py`)

- Contains the implementation of the Secure Information Handling (SIH) class.
- Provides methods for calculating hashes, encrypting and decrypting data, and generating digital signatures.
- Implements a custom hash function with features like HMAC, compression, and padding.

### Blockchain Module (`blockchain.py`)

- Implements the Blockchain class for managing the decentralized ledger.
- Includes methods for adding new blocks, transactions, and verifying blockchain integrity.
- Utilizes JSON serialization for persistence and load balancing.

### Utility Module (`util.py`)

- Provides utility functions for hash calculation, integrity verification, and blockchain data manipulation.
- Includes functions for generating random strings, intercepting messages, and compromising blockchain integrity for testing purposes.

## Usage

1. Install the required dependencies like rsa,cryptography and hashlib required`.
2. Execute `main.py` to run the demonstration script.
3. Follow the prompts to input data and observe the SIH and Blockchain functionalities.

