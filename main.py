from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os



MAXIMUM_BYTES = 128
k = MAXIMUM_BYTES



def pad_pkcs1_v15(message: bytes) -> bytes:
    """Apply PKCS#1 v1.5 padding (type 2) manually"""
    if len(message) > k - 11:
        raise ValueError("Message too long for PKCS#1 v1.5")

    padding_length = k - 3 - len(message)
    ps = b""

    while len(ps) < padding_length:
        byte = os.urandom(1)
        if byte != b'\x00':
            ps += byte

    return b'\x00\x02' + ps + b'\x00' + message



def rsa_encrypt_with_keys(message: bytes, public_key) -> int:
    """Encrypt a message using RSA with the provided public key"""
    # Extract the public exponent (e) and modulus (n) from the public key
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n

    # Convert the message to an integer
    message_int = int.from_bytes(message, byteorder='big')

    if message_int >= n:
        raise ValueError("Message must be less than the modulus (n).")

    # Perform RSA encryption
    return pow(message_int, e, n)



def rsa_decrypt_with_keys(ciphertext: int, private_key) -> bytes:
    """Decrypt a ciphertext using RSA with the provided private key"""
    # Extract the private exponent (d) and modulus (n) from the private key
    private_numbers = private_key.private_numbers()
    d = private_numbers.d
    n = private_numbers.public_numbers.n

    # Perform RSA decryption
    decrypted_int = pow(ciphertext, d, n)

    # Convert the decrypted integer back to bytes
    decrypted_bytes = decrypted_int.to_bytes(
        (decrypted_int.bit_length() + 7) // 8, byteorder='big'
    )

    # Ensure the leading '00' byte is preserved
    if len(decrypted_bytes) < k:
        decrypted_bytes = b'\x00' * (k - len(decrypted_bytes)) + decrypted_bytes

    return decrypted_bytes



def oracle_pkcs1_v15(ciphertext: int, public_key) -> bool:
    plaintext = rsa_decrypt_with_keys(ciphertext, public_key)
    if len(plaintext) != k:
        return False
    if not plaintext.startswith(b'\x00\x02'):
        return False
    return True  # padding PKCS#1 v1.5 OK


def blinding_naive(ciphertext: int, public_key, private_key) -> bytes:
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n

    # Start with a random blinding factor
    s0 = 2
    while True:
        blinded_ciphertext = (ciphertext * pow(s0, e, n)) % n
        if oracle_pkcs1_v15(blinded_ciphertext, private_key):
            return s0.to_bytes((s0.bit_length() + 7) // 8 or 1, byteorder='big')
        s0 += 1



def blinding(ciphertext: int, public_key, private_key) -> bytes:
    """Optimized blinding method for PKCS#1 v1.5 attack"""
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n

    # Start with a random blinding factor
    s0 = 2
    while True:
        # Ensure s0 is coprime with n
        if pow(s0, e, n) != 0:
            blinded_ciphertext = (ciphertext * pow(s0, e, n)) % n
            if oracle_pkcs1_v15(blinded_ciphertext, private_key):
                return s0.to_bytes((s0.bit_length() + 7) // 8 or 1, byteorder='big')
        s0 += 1



# Exemple d'utilisation
if __name__ == "__main__":
    # Générer une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=8*k
    )
    public_key = private_key.public_key()

    # Générer un message
    message = b"PKCS#1 v1.5!"
    print(f"Message original: {message.hex()}\n")

    # Ajouter du padding
    padded_message = pad_pkcs1_v15(message)
    print(f"Message avec padding (hex): {padded_message.hex()}\n")

    # Chiffrer le message
    ciphertext = rsa_encrypt_with_keys(padded_message, public_key)
    print(f"Message chiffré (hex): {ciphertext:x}\n")

    # Verifier si le cypher est pkcs compliant avec l'oracle
    is_compliant = oracle_pkcs1_v15(ciphertext, private_key)
    print(f"Le message chiffré est conforme à PKCS#1 v1.5: {is_compliant}\n")

    # Déchiffrer le message
    decrypted_message = rsa_decrypt_with_keys(ciphertext, private_key)
    print(f"Message déchiffré (hex): {decrypted_message.hex()}\n")

    # Recuperation de s0 via blinding
    s0 = blinding_naive(ciphertext, public_key, private_key)
    print(f"Valeur de s0 trouvée: {s0}\n")

    print(f"Cypher multiplié par s0 (hex): {hex(ciphertext*rsa_encrypt_with_keys(s0, public_key))}\n")

    # Déchiffrer le message avec la valeur de s0
    decrypted_message_with_s0 = rsa_decrypt_with_keys(ciphertext * rsa_encrypt_with_keys(s0, public_key), private_key)
    print(f"Message déchiffré avec s0 (hex): {decrypted_message_with_s0.hex()}\n")
