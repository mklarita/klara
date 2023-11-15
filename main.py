import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key():
    # Generate a random 128-bit key for AES encryption
    return os.urandom(16)


def pad_message(message):
    # Pad the message to be a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message)
    padded_message += padder.finalize()
    return padded_message


def unpad_message(padded_message):
    # Unpad the message after decryption
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message)
    message += unpadder.finalize()
    return message


def encrypt(key, plaintext, mode='CBC'):
    # Generate a random 128-bit IV for CBC mode
    iv = os.urandom(16) if mode == 'CBC' else None

    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(os.urandom(16)), backend=default_backend())
    else:
        raise ValueError("Invalid mode. Use 'CBC' or 'CTR'.")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext) if mode == 'CBC' else ciphertext


def decrypt(key, ciphertext, iv=None, mode='CBC'):
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(os.urandom(16)), backend=default_backend())
    else:
        raise ValueError("Invalid mode. Use 'CBC' or 'CTR'.")

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def modify_ciphertext_cbc(ciphertext, revoked_devices):
    # Modify CBC ciphertext based on revoked devices
    # Your logic here for modifying the ciphertext
    pass


def modify_ciphertext_ctr(ciphertext, revoked_devices):
    # Modify CTR ciphertext based on revoked devices
    # Your logic here for modifying the ciphertext
    pass


def revoke_devices(ciphertext, revoked_devices, mode='CBC'):
    if revoked_devices:
        if mode == 'CBC':
            ciphertext = modify_ciphertext_cbc(ciphertext, revoked_devices)
        elif mode == 'CTR':
            ciphertext = modify_ciphertext_ctr(ciphertext, revoked_devices)
    return ciphertext


def encode_with_revocation(message, revoked_devices, n, mode='CBC'):
    padded_message = pad_message(message)
    key = generate_key()

    # Encrypt the message
    if mode == 'CBC':
        iv, ciphertext = encrypt(key, padded_message, mode='CBC')
    elif mode == 'CTR':
        ciphertext = encrypt(key, padded_message, mode='CTR')
    else:
        raise ValueError("Invalid mode. Use 'CBC' or 'CTR'.")

    # If devices are revoked, modify ciphertext accordingly
    ciphertext = revoke_devices(ciphertext, revoked_devices, mode)

    return (key, ciphertext, iv if mode == 'CBC' else None)


# Example usage:
message = b'This is the message to encode.'
revoked_devices = {2, 4}  # For example, devices 2 and 4 are revoked
n = 6  # Total number of devices

encoded_data = encode_with_revocation(message, revoked_devices, n, mode='CBC')
