import hashlib
from Crypto.Cipher import PKCS1_OAEP

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
    return PKCS1_OAEP.new(public_key).encrypt(plaintext.encode('utf-8'))

def decrypt_message(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext).decode('utf-8')

def compute_sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()