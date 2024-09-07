from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Function to encrypt data
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)  # Use CBC (Cipher Block Chaining) mode
    iv = cipher.iv  # Initialization vector
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))  # Pad data
    return iv + ciphertext  # Return the IV + ciphertext for decryption

# Function to decrypt data
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract IV
    actual_ciphertext = ciphertext[16:]  # Extract the actual ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)  # Unpad decrypted data
    return decrypted_data.decode()

# Example usage
if __name__ == "__main__":
    key = get_random_bytes(16)  # AES-128 key (16 bytes)
    data = "Hello, AES encryption!"

    # Encrypt the data
    encrypted_data = aes_encrypt(key, data)
    print(f"Encrypted data: {encrypted_data}")

    # Decrypt the data
    decrypted_data = aes_decrypt(key, encrypted_data)
    print(f"Decrypted data: {decrypted_data}")
