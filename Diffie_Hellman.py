# Diffie-Hellman key exchange protocol using parameters from Constants.py.

from Constants import G, P


def private_key_from_char(ch: str) -> int:
    # Converts a single character to an integer to be used as a private key.
    # #e.g. '9' -> ASCII 57 -> private key 57
    
    return ord(ch)


def dh_public_value(private_key: int) -> int:
    # Compute the public value to share with the other user.
    # Formula: g^private_key mod p
    
    return pow(G, private_key, P)


def dh_shared_key(other_public: int, my_private: int) -> int:
    # Compute the shared secret using the other user's public value.
    # Formula: other_public^my_private mod p
    # Both users arrive at the same number without ever sharing their private key.
    
    return pow(other_public, my_private, P)