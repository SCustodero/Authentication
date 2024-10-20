from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as aes_padding
import os


class CryptoProject:
    # Vigenere Cipher Encryption using the alphabet as a dicitonary
    def vigenere_encrypt(self, plaintext, keyword):
        alpha = {
        'A': 0,
        'B': 1,
        'C': 2,
        'D': 3,
        'E': 4,
        'F': 5,
        'G': 6,
        'H': 7,
        'I': 8,
        'J': 9,
        'K': 10,
        'L': 11,
        'M': 12,
        'N': 13,
        'O': 14,
        'P': 15,
        'Q': 16,
        'R': 17,
        'S': 18,
        'T': 19,
        'U': 20,
        'V': 21,
        'W': 22,
        'X': 23,
        'Y': 24,
        'Z': 25
        }
        # Creates a list of the alphabet for indexing
        alpha_list = list(alpha)

        # Extends the keyword to the length of the plaintext
        i = 0
        extend_key = keyword
        while(len(extend_key) < len(plaintext)):
            extend_key += extend_key[i]
            i += 1
            if i == len(keyword):
                i = 0

        # Encrypts the plaintext by adding the corresponding values of the plaintext and the key
        ciphertext = ""
        for idx, letter in enumerate(plaintext):
            plain_value = alpha[letter]
            key_value = alpha[extend_key[idx]]
            ciphertext += alpha_list[plain_value + key_value if plain_value + key_value < 26 
                                    else plain_value + key_value - 26]

        return ciphertext
        

    # Vigenere Cipher Decryption
    def vigenere_decrypt(self, ciphertext, keyword):
        alpha = {
        'A': 0,
        'B': 1,
        'C': 2,
        'D': 3,
        'E': 4,
        'F': 5,
        'G': 6,
        'H': 7,
        'I': 8,
        'J': 9,
        'K': 10,
        'L': 11,
        'M': 12,
        'N': 13,
        'O': 14,
        'P': 15,
        'Q': 16,
        'R': 17,
        'S': 18,
        'T': 19,
        'U': 20,
        'V': 21,
        'W': 22,
        'X': 23,
        'Y': 24,
        'Z': 25
        }
        alpha_list = list(alpha)

        # Extends the keyword to the length of the ciphertext
        i = 0
        extend_key = keyword
        while(len(extend_key) < len(ciphertext)):
            extend_key += extend_key[i]
            i += 1
            if i == len(keyword):
                i = 0

        # Decrypts the ciphertext by subtracting the corresponding values of the ciphertext and the key
        plaintext = ""
        for idx, letter in enumerate(ciphertext):
            plain_value = alpha[letter]
            key_value = alpha[extend_key[idx]]
            plaintext += alpha_list[plain_value - key_value if plain_value + key_value >= 0 
                                    else plain_value - key_value + 26]

        return plaintext

        
    def aes_encrypt(self, plaintext, passwd):
        # Generates random salt and iv
        salt = os.urandom(16)
        iv = os.urandom(16)

        # Derives the key from the "key" and salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(passwd.encode())

        # AES Cipher used as encryptor
        cipher = Cipher(algorithms.AES(key=key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pads the plaintext
        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        # Encrypts the padded data
        ct = encryptor.update(padded_data) + encryptor.finalize()

        # Converts the necessary values to hex
        ct = ct.hex()
        salt = salt.hex()
        iv = iv.hex()

        return f"{salt}|{iv}|{ct}"

    def aes_decrypt(self, ciphertext, passwd):
        # Extracts the necessary values
        salt, iv, ct = ciphertext.split('|')

        # Derives the key from the "key" and salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(salt), iterations=100000, backend=default_backend())
        key = kdf.derive(passwd.encode())

        # AES Cipher used as decryptor
        cipher = Cipher(algorithms.AES(key=key), modes.CBC(bytes.fromhex(iv)), backend=default_backend())
        decryptor = cipher.decryptor()

        # Converts the ciphertext to bytes
        ct = bytes.fromhex(ct)
        
        # Decrypts the padded ciphertext
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        # Unpads the data
        unpadder = aes_padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Converts the data to a string
        plaintext = unpadded_data.decode()

        return plaintext

    def generate_rsa_keys(self, keyname):
        
        # Generate private and public keys
        private_key = rsa.generate_private_key(65537, 2048)
        public_key = private_key.public_key()

        # Derives the private key in PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Save private key to a file
        with open(keyname + '_private.pem', 'wb') as f:
            f.write(pem_private_key)

        # Derives the public key in PEM format
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save public key to a file
        with open(keyname + '_public.pem', 'wb') as f:
            f.write(pem_public_key)


    def rsa_encrypt(self, plaintext, public_key):
        # Load public key
        with open(public_key + '_public.pem', 'rb') as f:
            pKey = serialization.load_pem_public_key(f.read())
        # Encrypt plaintext
        ciphertext = pKey.encrypt(plaintext=bytes(plaintext, 'utf-8'), padding=padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(), label=None))

        return(ciphertext.hex())

    def rsa_decrypt(self, ciphertext, private_key):
        # Load ciphertext
        with open(ciphertext + '.txt', 'r') as cipher:
            ct = cipher.read()

        ct = bytes.fromhex(ct)

        # Load private key
        with open(private_key + '_private.pem', 'rb') as private:
            pk = serialization.load_pem_private_key(private.read(), password=None)

        # Decrypt ciphertext
        plaintext = pk.decrypt(ct, padding=padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(), label=None))
        
        return (plaintext.decode())

    def hash_string(self, input_string):
        # Hashes the string
        digest = hashes.Hash(algorithm=hashes.SHA256(), backend=default_backend())
        digest.update(bytes(input_string, 'utf-8'))
        hash_bytes = digest.finalize()

        return hash_bytes.hex()

    def verify_integrity(self, input_string, expected_hash):
        # Hashes the string
        hash_bytes = self.hash_string(input_string)

        # Compare hashes
        if hash_bytes == expected_hash:
            return True
        return False