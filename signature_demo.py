from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import random


# --- Sender Side ---
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message: bytes) -> bytes:
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return signature


# --- Receiver Side ---
def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


# --- Simulate Sending and Receiving ---
def main():
    private_key, public_key = generate_keys()
    message = b"Transfer $1000 to Alice"
    signature = sign_message(private_key, message)

    print("Message:", message.decode())
    print("Signature (base64):", base64.b64encode(signature).decode())

    is_valid = verify_signature(public_key, message, signature)

    if is_valid:
        print("✅ Signature is valid. Message is authentic.")
    else:
        print("❌ Signature is invalid. Message may be tampered.")


if __name__ == "__main__":
    main()
