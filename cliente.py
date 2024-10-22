import socket
import pyotp
import qrcode
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

# Função para cifrar dados
def cifrar_dados_aes_gcm(chave_sessao, dados):
    aesgcm = AESGCM(chave_sessao)
    nonce = os.urandom(12)
    dados_cifrados = aesgcm.encrypt(nonce, dados.encode('utf-8'), None)
    return nonce, dados_cifrados

# Função para decifrar a mensagem do servidor
def decifrar_dados_aes_gcm(chave_sessao, nonce, dados_cifrados):
    aesgcm = AESGCM(chave_sessao)
    dados_decifrados = aesgcm.decrypt(nonce, dados_cifrados, None)
    return dados_decifrados.decode('utf-8')

def cliente():
    # Interage com o usuário
    celular = input("Informe seu número de celular: ")

    # Gerando TOTP e QR Code
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=celular + "@restaurante.com", issuer_name="Restaurante Python")
    qr = qrcode.make(uri)
    qr.save("qr_code.png")
    img = Image.open("qr_code.png")
    img.show()

    # Valida o TOTP
    totp = pyotp.TOTP(secret)
    input("Escaneie o QR code e pressione Enter.")
    codigo_digitado = input("Digite o código TOTP exibido no aplicativo: ")

    if not totp.verify(codigo_digitado):
        print("Autenticação falhou.")
        return

    print("Autenticação bem-sucedida!")

    # Gera chave de sessão com PBKDF2
    senha_do_usuario = input("Por favor, insira uma senha para gerar a chave de sessão: ")
    salt = os.urandom(16)
    chave_sessao = hashlib.pbkdf2_hmac('sha256', senha_do_usuario.encode('utf-8'), salt, 100000)

    # Envia comprovante cifrado para o servidor
    comprovante_pagamento = input("Insira o comprovante de pagamento: ")
    nonce, comprovante_cifrado = cifrar_dados_aes_gcm(chave_sessao, comprovante_pagamento)

    # Conecta ao servidor e envia os dados
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Envia o tamanho do TOTP secret, seguido do secret em si
    client_socket.send(len(secret).to_bytes(4, byteorder='big'))  # Envia o tamanho do TOTP secret
    client_socket.send(secret.encode('utf-8'))  # Envia o TOTP secret

    # Envia a chave de sessão como binário
    client_socket.send(chave_sessao)  # Envia a chave de sessão
    client_socket.send(nonce)  # Envia o nonce
    client_socket.send(comprovante_cifrado)  # Envia o comprovante cifrado

    # Recebe a mensagem cifrada do servidor (horário de entrega)
    nonce_mensagem = client_socket.recv(12)
    mensagem_cifrada = client_socket.recv(1024)

    # Decifra a mensagem
    mensagem_decifrada = decifrar_dados_aes_gcm(chave_sessao, nonce_mensagem, mensagem_cifrada)
    print(f"Mensagem decifrada: {mensagem_decifrada}")

    client_socket.close()

if __name__ == "__main__":
    cliente()
