# Importation des bibliothèques nécessaires
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib
import binascii
import random

# 1. Génération des clés RSA (2048 bits)
key = RSA.generate(2048)
private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("Clés RSA générées et sauvegardées.")

# Chiffrement RSA
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

cipher_rsa = PKCS1_OAEP.new(public_key)
message_rsa = b"Message secret RSA"
ciphertext_rsa = cipher_rsa.encrypt(message_rsa)
print("Chiffrement RSA :", binascii.hexlify(ciphertext_rsa))

# Déchiffrement RSA
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_message_rsa = cipher_rsa.decrypt(ciphertext_rsa)
print("Message déchiffré RSA :", decrypted_message_rsa.decode())

# 2. Chiffrement AES
key_aes = get_random_bytes(16)
cipher_aes = AES.new(key_aes, AES.MODE_EAX)
message_aes = b"AES encryption example"
ciphertext_aes, tag_aes = cipher_aes.encrypt_and_digest(message_aes)
print("Chiffrement AES :", ciphertext_aes)

# Déchiffrement AES
cipher_aes = AES.new(key_aes, AES.MODE_EAX, nonce=cipher_aes.nonce)
decrypted_message_aes = cipher_aes.decrypt(ciphertext_aes)
print("Message déchiffré AES :", decrypted_message_aes.decode())

# 3. Chiffrement César
def caesar_cipher(text, shift):
    result = ""
    for i in text:
        if i.isalpha():
            shift_base = 65 if i.isupper() else 97
            result += chr((ord(i) - shift_base + shift) % 26 + shift_base)
        else:
            result += i
    return result

message_caesar = "HELLO"
shift = 3
cipher_text_caesar = caesar_cipher(message_caesar, shift)
print("Chiffrement César :", cipher_text_caesar)
print("Texte déchiffré César :", caesar_cipher(cipher_text_caesar, -shift))

# 4. Chiffrement Polybe
def polybius_cipher(text):
    square = [['A', 'B', 'C', 'D', 'E'], ['F', 'G', 'H', 'I', 'K'],
              ['L', 'M', 'N', 'O', 'P'], ['Q', 'R', 'S', 'T', 'U'],
              ['V', 'W', 'X', 'Y', 'Z']]
    text = text.upper().replace('J', 'I')
    cipher = ""
    for char in text:
        for row in range(5):
            if char in square[row]:
                cipher += str(row+1) + str(square[row].index(char)+1)
    return cipher

message_polybe = "HELLO"
cipher_text_polybe = polybius_cipher(message_polybe)
print("Chiffrement Polybe :", cipher_text_polybe)

# 5. Chiffrement Vigenère
def vigenere_cipher(text, key):
    result = []
    key = key.upper()
    for i in range(len(text)):
        char = text[i]
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            shift_base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result)

message_vigenere = "HELLO"
key_vigenere = "KEY"
cipher_text_vigenere = vigenere_cipher(message_vigenere, key_vigenere)
print("Chiffrement Vigenère :", cipher_text_vigenere)

# 6. Chiffrement Vernam
def vernam_cipher(text, key):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(text, key))

message_vernam = "HELLO"
key_vernam = "XMCKL"
cipher_text_vernam = vernam_cipher(message_vernam, key_vernam)
print("Chiffrement Vernam :", cipher_text_vernam)
print("Texte déchiffré Vernam :", vernam_cipher(cipher_text_vernam, key_vernam))

# 7. Hamming (Envoi et contrôle de message)
def calculate_parity_bits(data_bits):
    n = len(data_bits)
    result = list(data_bits)
    parity_positions = [2 ** i for i in range(n) if 2 ** i <= n]

    for p in parity_positions:
        count = sum(int(result[i]) for i in range(len(result)) if (i + 1) & p)
        result[p - 1] = str(count % 2)
    return ''.join(result)

message_hamming = "1011"
encoded_message_hamming = calculate_parity_bits(message_hamming)
print("Message encodé avec Hamming :", encoded_message_hamming)

# 8. Fonction de Hash (SHA-256)
def hash_function(data):
    sha = hashlib.sha256()
    sha.update(data.encode('utf-8'))
    return sha.hexdigest()

message_hash = "HELLO"
hashed_message = hash_function(message_hash)
print("Hash (SHA-256) :", hashed_message)

# 9. Contrôle par CRC (Cyclic Redundancy Check)
def crc_remainder(input_bitstring, polynomial_bitstring, initial_filler):
    polynomial_length = len(polynomial_bitstring)
    bitstring = input_bitstring + initial_filler
    for i in range(len(input_bitstring)):
        if bitstring[i] == '1':
            for j in range(len(polynomial_bitstring)):
                bitstring = (bitstring[:i+j] + str((int(bitstring[i + j]) ^ int(polynomial_bitstring[j]))) + bitstring[i + j + 1:])
    return bitstring[-len(initial_filler):]

message_crc = "11010011101100"
polynomial_crc = "1011"
remainder_crc = crc_remainder(message_crc, polynomial_crc, "000")
print("Reste CRC :", remainder_crc)

# 10. Diffie-Hellman (Partage de clés)
def diffie_hellman(p, g, private_key):
    return pow(g, private_key, p)

p_diffie = 23
g_diffie = 5
private_key_diffie = random.randint(1, p_diffie-1)
public_key_diffie = diffie_hellman(p_diffie, g_diffie, private_key_diffie)
print("Clé publique Diffie-Hellman :", public_key_diffie)

# 11. Chiffrement par Substitution
def substitution_cipher(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = text.upper()
    result = ""
    for char in text:
        if char in alphabet:
            result += key[alphabet.index(char)]
        else:
            result += char
    return result

message_substitution = "HELLO"
key_substitution = "QWERTYUIOPASDFGHJKLZXCVBNM"
cipher_text_substitution = substitution_cipher(message_substitution, key_substitution)
print("Chiffrement par Substitution :", cipher_text_substitution)

# Instructions pour exécuter le script en mode console sur VSCode
if __name__ == "__main__":
    print("\n--- Exécution en mode console sur VSCode ---\")
    print("1. Assurez-vous que vous avez installé toutes les bibliothèques nécessaires, comme PyCryptodome.")
    print("2. Appuyez sur F5 pour exécuter le script ou utilisez le terminal intégré en appuyant sur 'Ctrl+`'.")
    print("3. Assurez-vous que Python est bien configuré dans VSCode.")
    print("4. Vérifiez la sortie dans le terminal pour voir les résultats des différents algorithmes.")

           python script_name.py