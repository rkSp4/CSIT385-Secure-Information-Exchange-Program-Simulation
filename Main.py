# main.py
# Secure Information Exchange Program Simulation
# Ties together Diffie-Hellman key exchange and AES-128 encryption.

from Constants import G, P, BLOCK_SIZE, PAD_BYTE
from Diffie_Hellman import private_key_from_char, dh_public_value, dh_shared_key
from AES_Cipher import make_aes_key, chunk_message, encrypt_message, decrypt_message


# ── Display Helpers ──────────────────────────────────────────────────────────

def bytes_to_hex(b: bytes) -> str:
    return b.hex().upper()


def print_section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


# ── Simulation ───────────────────────────────────────────────────────────────

def simulate(private_key_char_a: str, private_key_char_b: str, message: str):
    print("=" * 60)
    print("   SECURE INFORMATION EXCHANGE PROGRAM SIMULATION")
    print(f"   Diffie-Hellman (p={P}, g={G})  +  AES-128")
    print("=" * 60)

    # Step 1: Private Keys
    print_section("STEP 1 — Private Keys")
    a = private_key_from_char(private_key_char_a)
    b = private_key_from_char(private_key_char_b)
    print(f"  User A  char='{private_key_char_a}'  decimal={a}  "
          f"binary={a:08b}  hex={a:02X}")
    print(f"  User B  char='{private_key_char_b}'  decimal={b}  "
          f"binary={b:08b}  hex={b:02X}")

    # Step 2: Public Values
    print_section("STEP 2 — Public Values (g^priv mod p)")
    pub_a = dh_public_value(a)
    pub_b = dh_public_value(b)
    print(f"  User A  Public Value = {G}^{a} mod {P} = {pub_a}")
    print(f"  User B  Public Value = {G}^{b} mod {P} = {pub_b}")

    # Step 3: Shared Secret
    print_section("STEP 3 — Shared Secret")
    shared_a = dh_shared_key(pub_b, a)
    shared_b = dh_shared_key(pub_a, b)
    print(f"  From A's side: {pub_b}^{a} mod {P} = {shared_a}")
    print(f"  From B's side: {pub_a}^{b} mod {P} = {shared_b}")
    if shared_a != shared_b:
        print("  ✗ ERROR: Shared secrets do not match!")
        return
    shared_secret = shared_a
    print(f"  ✓ Shared Secret = {shared_secret}")

    # Step 4: AES Key
    print_section("STEP 4 — AES-128 Key Derivation")
    aes_key = make_aes_key(shared_secret)
    print(f"  Shared secret integer : {shared_secret}")
    print(f"  AES-128 key (hex)     : {bytes_to_hex(aes_key)}")

    # Step 5: Chunking
    print_section("STEP 5 — Message Chunking & Padding")
    chunks = chunk_message(message)
    print(f"  Message : \"{message}\"")
    print(f"  Length  : {len(message)} chars → {len(chunks)} chunk(s) × 16 bytes")
    for i, ch in enumerate(chunks):
        printable = ''.join(
            chr(byte) if 32 <= byte < 127 else f'[{byte:02X}]' for byte in ch
        )
        print(f"    Chunk {i+1}: {bytes_to_hex(ch)}  \"{printable}\"")

    # Step 6: Encryption
    print_section("STEP 6 — AES-128 Encryption (ECB, chunk-by-chunk)")
    ciphertext = encrypt_message(message, aes_key)
    padded_plain = message.encode('ascii').ljust(len(chunks) * BLOCK_SIZE, bytes([PAD_BYTE]))
    print(f"  Plaintext  (hex): {bytes_to_hex(padded_plain)}")
    print(f"  Ciphertext (hex): {bytes_to_hex(ciphertext)}")
    print(f"  Ciphertext size : {len(ciphertext)} bytes")

    # Step 7: Decryption
    print_section("STEP 7 — Decryption by User B")
    decrypted = decrypt_message(ciphertext, aes_key)
    print(f"  Decrypted message : \"{decrypted}\"")
    if decrypted == message:
        print("  ✓ Message integrity verified — matches original!")
    else:
        print("  ✗ WARNING: Decrypted message does not match original!")

    print("\n" + "=" * 60)
    print("  Simulation complete.")
    print("=" * 60 + "\n")


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nWelcome to the Secure Information Exchange Program Simulation")
    print(f"Using: Diffie-Hellman (p={P}, g={G}) + AES-128\n")

    char_a = input("Enter User A's private key character (e.g. '9' for decimal 57): ").strip()
    if len(char_a) != 1:
        print("Error: Please enter a single ASCII character.")
        exit(1)

    char_b = input("Enter User B's private key character: ").strip()
    if len(char_b) != 1:
        print("Error: Please enter a single ASCII character.")
        exit(1)

    msg = input("Enter the message to send from User A to User B: ")
    if not msg:
        print("Error: Message cannot be empty.")
        exit(1)

    simulate(char_a, char_b, msg)