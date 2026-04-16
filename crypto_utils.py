import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def generate_rsa_keypair():

    """
    TODO:
    Generate and return an RSA key pair.

    Returns:
        (private_key, public_key)
    """

    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    return private_key, public_key


def serialize_public_key(public_key):

    """
    TODO:
    Convert the public key into a string format
    that can be sent through a socket.

    Example final format:
        PEM text string
    """

    return public_key.export_key().decode("utf-8")


def deserialize_public_key(key_data):

    """
    TODO:
    Convert the received string/PEM text
    back into a usable public key object.
    """

    return RSA.import_key(key_data)
    


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

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
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
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    plaintext = cipher.decrypt(ciphertext)
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