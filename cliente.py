import socket
import pyotp
import os
import hashlib
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Função para derivar chave com PBKDF2
def gerar_chave_sessao(senha, salt, iteracoes=100000):
    chave = hashlib.pbkdf2_hmac(
        'sha256',  # Função hash
        senha.encode('utf-8'),  # Senha
        salt,  # Salt
        iteracoes  # Número de iterações
    )
    return chave

# Função para cifrar dados com AES-GCM
def cifrar_dados(chave_sessao, dados):
    aesgcm = AESGCM(chave_sessao)
    nonce = os.urandom(12)  # Gera um nonce aleatório de 12 bytes
    dados_cifrados = aesgcm.encrypt(nonce, dados.encode('utf-8'), None)
    return nonce, dados_cifrados

# Função para decifrar dados com AES-GCM
def decifrar_dados(chave_sessao, nonce, dados_cifrados):
    aesgcm = AESGCM(chave_sessao)
    dados_decifrados = aesgcm.decrypt(nonce, dados_cifrados, None)
    return dados_decifrados.decode('utf-8')

# Função para realizar o login com autenticação 2FA
def login_cliente():
    # Coleta do nome de usuário e número de celular
    usuario = input("Informe seu nome de usuário: ")
    celular = input("Informe seu número de celular: ")

    # Envia as informações de login para o servidor
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    
    # Envia o nome de usuário e celular para o servidor
    client_socket.send(usuario.encode('utf-8'))
    client_socket.send(celular.encode('utf-8'))

    # Recebe o QR Code do servidor
    with open("qr_code.png", "wb") as f:
        qr_code = client_socket.recv(4096)
        f.write(qr_code)
    
    img = Image.open("qr_code.png")
    img.show()

    # O usuário insere o código TOTP
    codigo_totp = input("Digite o código TOTP exibido no aplicativo de autenticação: ")

    # Envia o código TOTP para o servidor
    client_socket.send(codigo_totp.encode('utf-8'))

    # Recebe a resposta do servidor
    resposta = client_socket.recv(1024).decode('utf-8')
    print(resposta)

    # Caso o login tenha sido bem-sucedido, derivamos a chave de sessão
    if "sucesso" in resposta:
        senha = input("Insira sua senha para derivar a chave de sessão: ")
        salt = client_socket.recv(16)  # Recebe o salt gerado pelo servidor
        chave_sessao = gerar_chave_sessao(senha, salt)
        print(f"Chave de sessão gerada: {chave_sessao.hex()}")

        # Parte 5: Escolha do prato
        prato = input("Escolha o prato que deseja pedir (Pizza, Hambúrguer, Sushi): ")
        nonce_prato, prato_cifrado = cifrar_dados(chave_sessao, prato)
        client_socket.send(nonce_prato)
        client_socket.send(prato_cifrado)

        # Parte 6: Enviar pagamento cifrado
        pagamento = input("Digite o comprovante de pagamento: ")
        nonce_pagamento, pagamento_cifrado = cifrar_dados(chave_sessao, pagamento)
        client_socket.send(nonce_pagamento)
        client_socket.send(pagamento_cifrado)

        # Parte 9: Receber mensagem cifrada do servidor (horário de entrega)
        nonce_mensagem = client_socket.recv(12)
        mensagem_cifrada = client_socket.recv(1024)
        mensagem_decifrada = decifrar_dados(chave_sessao, nonce_mensagem, mensagem_cifrada)
        print(f"Mensagem do servidor: {mensagem_decifrada}")
    
    client_socket.close()

if __name__ == "__main__":
    login_cliente()
