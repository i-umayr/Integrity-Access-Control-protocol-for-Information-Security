import json
import hashlib

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.load_chain()  # Load the blockchain from file when creating a new instance

    def load_chain(self):
        try:
            with open("blockchain.json", "r") as f:
                data = f.read()
                if data:  # Check if the file is not empty
                    self.chain = json.loads(data, object_hook=self.hex_to_bytes)
                else:
                    self.chain = []
        except FileNotFoundError:
            # If file not found, start with an empty chain
            self.chain = []
        except json.decoder.JSONDecodeError:
            print("Error loading blockchain. File contains invalid JSON data.")
            self.chain = []

    def save_chain(self):
        def convert_to_serializable(obj):
            if isinstance(obj, bytes):
                return obj.hex()  # Convert bytes to hexadecimal string
            return obj

        with open("blockchain.json", "w") as f:
            json.dump(self.chain, f, default=convert_to_serializable)

    def new_block(self, previous_hash=None):
        """
        Create a new block in the blockchain.
        """
        index = len(self.chain) + 1  # Increment index properly
        if previous_hash is None and len(self.chain) > 0:
            previous_hash = self.hash(self.chain[-1])  # Use the hash of the last block as previous hash
        block = {
            'index': index,
            'transactions': self.current_transactions,
            'previous_hash': previous_hash,
        }

        self.chain.append(block)
        self.save_chain()  # Save the blockchain after adding a new block
        return block

    def new_transaction(self, data):
        """
        Add a new transaction to the blockchain.
        """
        self.current_transactions.append(data)

    def hash(self, block):
        """
        Create a SHA-256 hash of a block.
        """
        block_string = json.dumps(block, sort_keys=True, default=self.convert_to_serializable).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def convert_to_serializable(obj):
        if isinstance(obj, bytes):
            return obj.hex()  # Convert bytes to hexadecimal string
        return obj

    @staticmethod
    def hex_to_bytes(dct):
        """
        Convert hexadecimal strings back to bytes in JSON deserialization.
        """
        for key, value in dct.items():
            if isinstance(value, str) and len(value) == 64:  # Check if it's a hexadecimal string
                try:
                    dct[key] = bytes.fromhex(value)
                except ValueError:
                    pass  # If conversion fails, leave it unchanged
        return dct