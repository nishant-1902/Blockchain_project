from datetime import datetime
from .hash_util import generate_sha256_hash


class Block:
    """
    Represents a single block in the blockchain.
    
    Attributes:
        index (int): The position of this block in the blockchain.
        timestamp (datetime): The creation time of the block.
        data (dict or str): The data/transactions contained in the block.
        previous_hash (str): The SHA-256 hash of the previous block.
        hash (str): The SHA-256 hash of this block.
        nonce (int): The proof-of-work counter.
    """
    
    def __init__(self, index, data, previous_hash="0"):
        """
        Initialize a new block.
        
        Args:
            index (int): The index of this block in the chain.
            data (dict or str): The data/transactions to store in the block.
            previous_hash (str): The hash of the previous block. Defaults to "0" for genesis block.
        """
        self.index = index
        self.timestamp = datetime.utcnow()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """
        Calculate the SHA-256 hash of this block.
        
        Returns:
            str: The hexadecimal SHA-256 hash of the block.
        """
        block_string = f"{self.index}{self.timestamp.isoformat()}{self.data}{self.previous_hash}{self.nonce}"
        return generate_sha256_hash(block_string)
    
    def proof_of_work(self, difficulty=2):
        """
        Perform proof-of-work by finding a nonce that produces a hash with the required difficulty.
        
        Difficulty is defined as the number of leading zeros in the hash.
        
        Args:
            difficulty (int): The number of leading zeros required in the hash. Defaults to 2.
        
        Returns:
            str: The valid hash after proof-of-work is completed.
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        return self.hash
    
    def to_dict(self):
        """
        Convert the block to a dictionary representation.
        
        Returns:
            dict: A dictionary containing all block attributes.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "nonce": self.nonce,
        }
    
    def __repr__(self):
        return f"<Block index={self.index} hash={self.hash[:12]}... nonce={self.nonce}>"
