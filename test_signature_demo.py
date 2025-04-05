import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from signature_demo import generate_keys, sign_message, verify_signature


@pytest.fixture
def keys():
    private_key, public_key = generate_keys()
    return private_key, public_key


@pytest.fixture
def message():
    return b"Test message"


def test_key_generation(keys):
    private_key, public_key = keys
    assert isinstance(
        private_key, rsa.RSAPrivateKey
    ), "Private key is not an instance of RSAPrivateKey"
    assert isinstance(
        public_key, rsa.RSAPublicKey
    ), "Public key is not an instance of RSAPublicKey"


def test_sign_message(keys, message):
    private_key, _ = keys
    signature = sign_message(private_key, message)
    assert isinstance(signature, bytes), "Signature is not of type bytes"
    assert len(signature) > 0, "Signature is empty"


def test_verify_signature_valid(keys, message):
    private_key, public_key = keys
    signature = sign_message(private_key, message)
    assert verify_signature(
        public_key, message, signature
    ), "Valid signature verification failed"


def test_verify_signature_tampered_message(keys, message):
    private_key, public_key = keys
    signature = sign_message(private_key, message)
    tampered_message = b"Tampered message"
    assert not verify_signature(
        public_key, tampered_message, signature
    ), "Tampered message verification passed"


def test_verify_signature_tampered_signature(keys, message):
    private_key, public_key = keys
    signature = sign_message(private_key, message)
    tampered_signature = signature[:-1] + b"\x00"
    assert not verify_signature(
        public_key, message, tampered_signature
    ), "Tampered signature verification passed"


def test_generate_keys():
    private_key, public_key = generate_keys()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_sign_and_verify():
    private_key, public_key = generate_keys()
    message = b"Test message"
    signature = sign_message(private_key, message)
    assert verify_signature(public_key, message, signature) is True


def test_verify_tampered_message():
    private_key, public_key = generate_keys()
    message = b"Original message"
    tampered_message = b"Tampered message"
    signature = sign_message(private_key, message)
    assert verify_signature(public_key, tampered_message, signature) is False


def test_verify_tampered_signature():
    private_key, public_key = generate_keys()
    message = b"Original message"
    signature = sign_message(private_key, message)
    tampered_signature = signature[:-1] + b"\x00"
    assert verify_signature(public_key, message, tampered_signature) is False
