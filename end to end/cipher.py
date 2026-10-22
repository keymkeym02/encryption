from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generatePrivateAndPublicKey():
    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Get public key
    public_key = private_key.public_key()
    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Save public key
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public)
    # Save private key
    with open('private_key.pem', 'wb') as f:
        f.write(pem_private)
    return pem_public

#Load Receiver Public Key
def loadReceiverPublicKey(message):
    receiver_public_key = serialization.load_pem_public_key(message)
    return receiver_public_key

# Encrypt Message using the receiver's public key
def encryptMessage(message, public_key):
    
    encryptedMessage = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encryptedMessage

def decryptMessage(encryptedMessage):
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    return private_key.decrypt(
        encryptedMessage,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
