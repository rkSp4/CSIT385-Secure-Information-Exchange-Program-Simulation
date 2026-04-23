# AES-128 encryption and decryption using the shared secret from Diffie-Hellman.

from Crypto.Cipher import AES
from Constants import BLOCK_SIZE, PAD_BYTE


def make_aes_key(shared_secret: int) -> bytes:
    # Derive a 16-byte AES-128 key from the shared secret integer.
    # The secret is converted to bytes, then tiled to fill exactly 16 bytes.
    # e.g. secret=109 (0x6D) -> b'\x6d' tiled -> b'\x6d\x6d\x6d...' (16 bytes)
    
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8 or 1, 'big'
    )
    key = (secret_bytes * (BLOCK_SIZE // len(secret_bytes) + 1))[:BLOCK_SIZE]
    return key


def chunk_message(message: str) -> list[bytes]:  
    # Split a message into 16-byte (128-bit) chunks.
    # If the last chunk is shorter than 16 bytes, pad it with '@' (0x40).
    
    raw = message.encode('ascii')
    chunks = []
    for i in range(0, max(len(raw), 1), BLOCK_SIZE):
        chunk = raw[i:i + BLOCK_SIZE]
        if len(chunk) < BLOCK_SIZE:
            chunk = chunk + bytes([PAD_BYTE] * (BLOCK_SIZE - len(chunk)))
        chunks.append(chunk)
    return chunks


def encrypt_message(plaintext: str, aes_key: bytes) -> bytes:
    # Encrypt a plaintext message with AES-128 in ECB mode, chunk by chunk.
    # Returns the concatenated ciphertext bytes.
    
    chunks = chunk_message(plaintext)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = b''
    for chunk in chunks:
        ciphertext += cipher.encrypt(chunk)
    return ciphertext


def decrypt_message(ciphertext: bytes, aes_key: bytes) -> str:
    # Decrypt AES-128 ECB ciphertext block by block.
    # Strips trailing '@' padding from the result.
    
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext_bytes = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext_bytes += cipher.decrypt(block)
    return plaintext_bytes.rstrip(bytes([PAD_BYTE])).decode('ascii')