import hashlib


def generate_rsa_keypair():
    """
    TODO:
    Generate and return an RSA key pair.

    Returns:
        (private_key, public_key)
    """
    return None, None


def serialize_public_key(public_key):
    """
    TODO:
    Convert the public key into a string format
    that can be sent through a socket.

    Example final format:
        PEM text string
    """
    return "PUBLIC_KEY_PLACEHOLDER"


def deserialize_public_key(key_data):
    """
    TODO:
    Convert the received string/PEM text
    back into a usable public key object.
    """
    return key_data


def encrypt_message(plaintext, public_key):
    """
    TODO:
    Encrypt plaintext using the given public key.

    Args:
        plaintext (str): message to encrypt
        public_key: recipient's public key

    Returns:
        bytes or encoded string
    """
    return b"ENCRYPTED_PLACEHOLDER"


def decrypt_message(ciphertext, private_key):
    """
    TODO:
    Decrypt ciphertext using the given private key.

    Args:
        ciphertext (bytes): encrypted data
        private_key: owner's private key

    Returns:
        str: decrypted plaintext
    """
    return "DECRYPTED_PLACEHOLDER"


def compute_sha256(message):
    """
    Compute SHA256 hash of a string message.

    Args:
        message (str)

    Returns:
        str: hexadecimal SHA256 digest
    """
    return hashlib.sha256(message.encode()).hexdigest()