import socket
import pyotp
import qrcode
import os
import hashlib
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

# Função para gerar e enviar o QR Code para o cliente
def gerar_qr_code(totp_secret, conn):
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name="usuario@sistema.com", issuer_name="Sistema 2FA")
    qr = qrcode.make(uri)
    qr.save("qr_code.png")

    # Envia o QR Code para o cliente
    with open("qr_code.png", "rb") as f:
        conn.send(f.read())

# Função para realizar o login do usuário
def login_servidor(conn):
    # Recebe o nome de usuário e celular do cliente
    usuario = conn.recv(1024).decode('utf-8')
    celular = conn.recv(1024).decode('utf-8')
    print(f"Usuário: {usuario}, Celular: {celular}")

    # Gera o segredo TOTP
    secret = pyotp.random_base32()

    # Gera e envia o QR Code para o cliente
    gerar_qr_code(secret, conn)

    # Valida o TOTP inserido pelo cliente
    totp = pyotp.TOTP(secret)
    codigo_totp = conn.recv(1024).decode('utf-8')

    if totp.verify(codigo_totp):
        conn.send("Autenticação de dois fatores bem-sucedida! Login com sucesso.".encode('utf-8'))
        # Gera salt para derivar a chave de sessão
        salt = os.urandom(16)
        conn.send(salt)

        # Parte 5: Receber e decifrar prato cifrado
        nonce_prato = conn.recv(12)
        prato_cifrado = conn.recv(1024)
        prato = decifrar_dados(salt, nonce_prato, prato_cifrado)
        print(f"Prato escolhido: {prato}")

        # Parte 6: Receber e decifrar pagamento
        nonce_pagamento = conn.recv(12)
        pagamento_cifrado = conn.recv(1024)
        pagamento = decifrar_dados(salt, nonce_pagamento, pagamento_cifrado)
        print(f"Pagamento recebido: {pagamento}")

        # Parte 8: Enviar mensagem cifrada com horário de entrega
        mensagem = "Seu pedido chegará às 20:00."
        nonce_mensagem, mensagem_cifrada = cifrar_dados(salt, mensagem)
        conn.send(nonce_mensagem)
        conn.send(mensagem_cifrada)

    else:
        conn.send("Falha na autenticação de dois fatores. Tente novamente.".encode('utf-8'))
        conn.close()

def servidor():
    # Configurando o servidor para escutar conexões
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))  # Servidor escutando na porta 12345
    server_socket.listen(1)
    print("Servidor aguardando conexões...")

    # Aceita uma conexão
    conn, addr = server_socket.accept()
    print(f"Conexão estabelecida com {addr}")

    # Recebe o código TOTP e a chave de sessão gerada pelo cliente
    totp_secret_length = int.from_bytes(conn.recv(4), byteorder='big')  # Recebe o tamanho do TOTP
    totp_secret = conn.recv(totp_secret_length).decode('utf-8')  # Recebe o TOTP como texto com tamanho dinâmico
    chave_sessao = conn.recv(32)  # Recebe a chave de sessão como binário (32 bytes)

    # Recebe o nonce e o comprovante cifrado
    nonce_comprovante = conn.recv(12)  # Recebe o nonce de 12 bytes para o comprovante
    comprovante_cifrado = conn.recv(1024)  # Recebe o comprovante cifrado como binário

    # Recebe o nonce e o pedido cifrado
    nonce_pedido = conn.recv(12)  # Recebe o nonce de 12 bytes para o pedido
    pedido_cifrado = conn.recv(1024)  # Recebe o pedido cifrado como binário

    # Valida o TOTP (pode comparar com o TOTP do servidor se quiser)
    totp = pyotp.TOTP(totp_secret)
    print("Código TOTP validado com sucesso no servidor.")

    # Decifra o comprovante cifrado
    comprovante_decifrado = decifrar_dados_aes_gcm(chave_sessao, nonce_comprovante, comprovante_cifrado)
    print(f"Comprovante decifrado: {comprovante_decifrado}")

    # Decifra o pedido cifrado
    pedido_decifrado = decifrar_dados_aes_gcm(chave_sessao, nonce_pedido, pedido_cifrado)
    print(f"Pedido decifrado: {pedido_decifrado}")

    # Envia a mensagem cifrada para o cliente (horário de entrega)
    horario_entrega = "Seu pedido chegará às 20:00."
    aesgcm = AESGCM(chave_sessao)
    nonce_mensagem = os.urandom(12)
    mensagem_cifrada = aesgcm.encrypt(nonce_mensagem, horario_entrega.encode('utf-8'), None)

    # Envia nonce e a mensagem cifrada para o cliente
    conn.send(nonce_mensagem)
    conn.send(mensagem_cifrada)

    conn.close()

if __name__ == "__main__":
    servidor()
   
