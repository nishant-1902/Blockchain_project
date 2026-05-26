import json
from datetime import datetime
from .block import Block
from .hash_util import generate_sha256_hash


class Blockchain:
    """
    Manages the blockchain including creation, validation, and persistence.
    
    Attributes:
        chain (list): List of Block objects in the blockchain.
        difficulty (int): The proof-of-work difficulty level.
    """
    
    def __init__(self, difficulty=2):
        """
        Initialize a new blockchain.
        
        Args:
            difficulty (int): The proof-of-work difficulty level. Defaults to 2.
        """
        self.chain = []
        self.difficulty = difficulty
    
    def create_genesis_block(self):
        """
        Create and add the genesis block (first block) to the blockchain.
        
        The genesis block has index 0 and previous_hash of "0".
        
        Returns:
            Block: The created genesis block.
        """
        genesis_block = Block(index=0, data="Genesis Block", previous_hash="0")
        genesis_block.proof_of_work(self.difficulty)
        self.chain.append(genesis_block)
        return genesis_block
    
    def get_latest_block(self):
        """
        Retrieve the most recent block in the blockchain.
        
        Returns:
            Block: The last block in the chain.
        
        Raises:
            IndexError: If the chain is empty.
        """
        if not self.chain:
            raise IndexError("Blockchain is empty. Create genesis block first.")
        return self.chain[-1]
    
    def add_block(self, data):
        """
        Mine and add a new block to the blockchain.
        
        Args:
            data (dict or str): The data/transactions to store in the new block.
        
        Returns:
            Block: The newly created and mined block.
        
        Raises:
            IndexError: If the chain is empty (no genesis block).
        """
        if not self.chain:
            raise IndexError("Blockchain is empty. Create genesis block first.")
        
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=latest_block.hash
        )
        new_block.proof_of_work(self.difficulty)
        self.chain.append(new_block)
        return new_block
    
    def is_chain_valid(self):
        """
        Validate the integrity of the entire blockchain.
        
        Checks:
        1. Genesis block has previous_hash of "0"
        2. Each block's index is correct
        3. Each block's hash is calculated correctly
        4. Each block's previous_hash matches the previous block's hash
        5. Each block's hash meets the proof-of-work difficulty requirement
        
        Returns:
            bool: True if the chain is valid, False otherwise.
        """
        if not self.chain:
            return False
        
        # Validate genesis block
        genesis = self.chain[0]
        if genesis.previous_hash != "0":
            print(f"Invalid genesis block: previous_hash should be '0', got {genesis.previous_hash}")
            return False
        
        # Validate all other blocks
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check index
            if current_block.index != i:
                print(f"Invalid index at block {i}: expected {i}, got {current_block.index}")
                return False
            
            # Check hash calculation
            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid hash at block {i}: hash mismatch")
                return False
            
            # Check previous hash link
            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid previous_hash at block {i}: chain is broken")
                return False
            
            # Check proof-of-work
            target = "0" * self.difficulty
            if not current_block.hash.startswith(target):
                print(f"Invalid proof-of-work at block {i}: hash does not meet difficulty")
                return False
        
        return True
    
    def get_chain(self):
        """
        Retrieve the entire blockchain as a list of dictionaries.
        
        Returns:
            list: List of dictionaries representing each block in the chain.
        """
        return [block.to_dict() for block in self.chain]
    
    def get_block_by_index(self, index):
        """
        Retrieve a specific block by its index.
        
        Args:
            index (int): The index of the block to retrieve.
        
        Returns:
            Block: The block at the specified index, or None if not found.
        """
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def tamper_detection(self):
        """
        Detect if any blocks in the chain have been modified (tampered with).
        
        Returns:
            dict: Contains 'is_tampered' (bool) and 'tampered_blocks' (list of indices).
        """
        tampered_blocks = []
        
        for i, block in enumerate(self.chain):
            original_hash = block.hash
            calculated_hash = block.calculate_hash()
            
            if original_hash != calculated_hash:
                tampered_blocks.append(i)
        
        return {
            "is_tampered": len(tampered_blocks) > 0,
            "tampered_blocks": tampered_blocks,
            "total_blocks": len(self.chain),
        }
    
    def save_chain_to_db(self, db_session=None):
        """
        Persist the blockchain to the SQLite database using BlockchainRecord model.
        
        Args:
            db_session: SQLAlchemy database session. If None, attempts to import from models.
        
        Returns:
            bool: True if save was successful, False otherwise.
        """
        if db_session is None:
            try:
                from database.models import db
                db_session = db.session
            except ImportError:
                try:
                    from ICIDS.database.models import db
                    db_session = db.session
                except ImportError:
                    print("Warning: Could not import database session for blockchain persistence.")
                    return False
        
        try:
            from database.models import BlockchainRecord
        except ImportError:
            try:
                from ICIDS.database.models import BlockchainRecord
            except ImportError:
                print("Warning: BlockchainRecord model not found.")
                return False
        
        try:
            for block in self.chain:
                existing = BlockchainRecord.query.filter_by(block_index=block.index).first()
                
                if existing:
                    existing.block_hash = block.hash
                    existing.previous_hash = block.previous_hash
                    existing.data = json.dumps(block.data) if isinstance(block.data, dict) else block.data
                    existing.nonce = block.nonce
                else:
                    record = BlockchainRecord(
                        block_index=block.index,
                        block_hash=block.hash,
                        previous_hash=block.previous_hash,
                        data=json.dumps(block.data) if isinstance(block.data, dict) else block.data,
                        nonce=block.nonce,
                        timestamp=block.timestamp,
                    )
                    db_session.add(record)
            
            db_session.commit()
            return True
        except Exception as e:
            print(f"Error saving blockchain to database: {e}")
            db_session.rollback()
            return False
    
    def load_chain_from_db(self, db_session=None):
        """
        Load the blockchain from the SQLite database using BlockchainRecord model.
        
        Args:
            db_session: SQLAlchemy database session. If None, attempts to import from models.
        
        Returns:
            bool: True if load was successful, False otherwise.
        """
        if db_session is None:
            try:
                from database.models import db
                db_session = db.session
            except ImportError:
                try:
                    from ICIDS.database.models import db
                    db_session = db.session
                except ImportError:
                    print("Warning: Could not import database session for blockchain loading.")
                    return False
        
        try:
            from database.models import BlockchainRecord
        except ImportError:
            try:
                from ICIDS.database.models import BlockchainRecord
            except ImportError:
                print("Warning: BlockchainRecord model not found.")
                return False
        
        try:
            self.chain = []
            records = BlockchainRecord.query.order_by(BlockchainRecord.block_index).all()
            
            for record in records:
                try:
                    data = json.loads(record.data)
                except (json.JSONDecodeError, TypeError):
                    data = record.data
                
                block = Block(
                    index=record.block_index,
                    data=data,
                    previous_hash=record.previous_hash
                )
                block.hash = record.block_hash
                block.nonce = record.nonce
                block.timestamp = record.timestamp
                
                self.chain.append(block)
            
            return True
        except Exception as e:
            print(f"Error loading blockchain from database: {e}")
            return False
    
    def __repr__(self):
        return f"<Blockchain length={len(self.chain)} difficulty={self.difficulty}>"
