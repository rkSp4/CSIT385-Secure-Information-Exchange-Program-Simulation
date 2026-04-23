# Shared parameters that are used across the program.

# Diffie-Hellman parameters
P = 199   # prime modulus
G = 127   # generator

# AES-128 block size
BLOCK_SIZE = 16   # 16 bytes = 128 bits

# Padding character: '@' = ASCII 64 = 0x40 = 01000000
PAD_BYTE = ord('@')