import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def generate_rsa_keypair():

    """
    TODO:
    Generate and return an RSA key pair.

    Returns:
        (private_key, public_key)
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
        )
    
    public_key = private_key.public_key()
    
    return private_key, public_key


def serialize_public_key(public_key):

    """
    TODO:
    Convert the public key into a string format
    that can be sent through a socket.

    Example final format:
        PEM text string
    """

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem.decode("utf-8")


def deserialize_public_key(key_data):

    """
    TODO:
    Convert the received string/PEM text
    back into a usable public key object.
    """

    public_key = load_pem_public_key(key_data.encode("utf-8"))
    return public_key
    


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

    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


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
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode("utf-8")


def compute_sha256(message):
    """
    Compute SHA256 hash of a string message.

    Args:
        message (str)

    Returns:
        str: hexadecimal SHA256 digest
    """
    return hashlib.sha256(message.encode()).hexdigest()