import hashlib
import json


def generate_sha256_hash(data):
    """
    Generate a SHA-256 hash for the provided data.
    
    Args:
        data (str, dict, or bytes): The data to hash. If dict, it will be JSON serialized.
    
    Returns:
        str: The hexadecimal SHA-256 hash string.
    """
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    if isinstance(data, str):
        data = data.encode("utf-8")
    
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8")
    
    return hashlib.sha256(data).hexdigest()


def verify_hash(data, provided_hash):
    """
    Verify that the provided hash matches the SHA-256 hash of the data.
    
    Args:
        data (str, dict, or bytes): The data to verify.
        provided_hash (str): The hash to compare against.
    
    Returns:
        bool: True if hashes match, False otherwise.
    """
    computed_hash = generate_sha256_hash(data)
    return computed_hash == provided_hash


def generate_merkle_root(list_of_hashes):
    """
    Generate a Merkle root from a list of hashes.
    
    A Merkle tree is built by recursively hashing pairs of hashes until a single root remains.
    This provides an efficient way to verify the integrity of a set of transactions.
    
    Args:
        list_of_hashes (list): A list of hexadecimal hash strings.
    
    Returns:
        str: The hexadecimal hash representing the Merkle root.
    
    Raises:
        ValueError: If the list is empty.
    """
    if not list_of_hashes:
        raise ValueError("Cannot generate Merkle root from empty list of hashes.")
    
    hashes = list_of_hashes.copy()
    
    if len(hashes) == 1:
        return hashes[0]
    
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            parent_hash = generate_sha256_hash(combined)
            next_level.append(parent_hash)
        
        hashes = next_level
    
    return hashes[0]
