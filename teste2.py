import os
import base64
import json
import time
import qrcode
import secrets
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from pyotp import TOTP

# Constantes
SALT_SIZE = 16
KEY_SIZE = 32  # Para AES-256
IV_SIZE = 16  # Tamanho do IV para AES
ITERATIONS = 100000

def generate_salt():
    return get_random_bytes(SALT_SIZE)

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_data(key, iv, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + tag + ciphertext).decode('utf-8')

def decrypt_data(key, encrypted_data):
    raw_data = base64.b64decode(encrypted_data)
    iv, tag, ciphertext = raw_data[:IV_SIZE], raw_data[IV_SIZE:IV_SIZE+16], raw_data[IV_SIZE+16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted_data = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
    return decrypted_data.decode('utf-8')

def create_totp(secret):
    totp = TOTP(secret)
    return totp.now(), totp.provisioning_uri("user@example.com", issuer="iFoodSimulator")

def main():
    print("Bem-vindo ao simulador de pedido do iFood!")
    
    # Escolha do prato
    prato = input("Escolha um prato de comida (ex: Pizza, Sushi): ")

    # Solicitação do número de celular
    celular = input("Digite seu número de celular: ")

    # Geração do segredo TOTP
    secret = base64.b32encode(secrets.token_bytes(10)).decode('utf-8')
    totp_code, provisioning_uri = create_totp(secret)
    print(f"Use o QR Code abaixo para autenticação (código TOTP: {totp_code}):")
    img = qrcode.make(provisioning_uri)
    img.show()

    # Validação do código TOTP
    user_totp_code = input("Digite o código TOTP que você recebeu: ")
    if user_totp_code != totp_code:
        print("Código TOTP inválido!")
        return

    # Derivação da chave
    password = getpass("Digite uma senha para a chave de sessão: ")
    salt = generate_salt()
    key = derive_key(password, salt)

    # Pagamento e cifragem do comprovante
    comprovante = input("Digite o comprovante de pagamento: ")
    iv = get_random_bytes(IV_SIZE)
    encrypted_receipt = encrypt_data(key, iv, comprovante)

    print(f"Comprovante cifrado: {encrypted_receipt}")

    # Decifragem do comprovante
    decrypted_receipt = decrypt_data(key, encrypted_receipt)
    print(f"Comprovante decifrado: {decrypted_receipt}")

    # Envio da mensagem cifrada para o usuário
    mensagem = f"Seu pedido de {prato} deve chegar em 30 minutos."
    encrypted_message = encrypt_data(key, iv, mensagem)
    print(f"Mensagem cifrada enviada: {encrypted_message}")

    # Simulação da decifragem da mensagem recebida pelo usuário
    decrypted_message = decrypt_data(key, encrypted_message)
    print(f"Mensagem recebida: {decrypted_message}")

if __name__ == "__main__":
    main()
