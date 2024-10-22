import socket
import pyotp
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Função para decifrar dados
def decifrar_dados_aes_gcm(chave_sessao, nonce, dados_cifrados):
    aesgcm = AESGCM(chave_sessao)
    dados_decifrados = aesgcm.decrypt(nonce, dados_cifrados, None)
    return dados_decifrados.decode('utf-8')

def servidor():
    # Configurando o servidor para escutar conexões
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))  # Servidor escutando na porta 12345
    server_socket.listen(1)
    print("Servidor aguardando conexões...")

    # Aceita uma conexão
    conn, addr = server_socket.accept()
    print(f"Conexão estabelecida com {addr}")

    # Recebe o TOTP secret como texto UTF-8
    totp_secret_length = int.from_bytes(conn.recv(4), byteorder='big')  # Recebe o tamanho do TOTP
    totp_secret = conn.recv(totp_secret_length).decode('utf-8')  # Recebe o TOTP como texto com tamanho dinâmico

    # Recebe a chave de sessão como binário (32 bytes)
    chave_sessao = conn.recv(32)  # Recebe a chave de sessão como binário (não decodifica)

    # Recebe o nonce e o comprovante cifrado
    nonce = conn.recv(12)  # Recebe o nonce de 12 bytes
    comprovante_cifrado = conn.recv(1024)  # Recebe o comprovante cifrado como binário

    # Valida o TOTP (pode comparar com o TOTP do servidor se quiser)
    totp = pyotp.TOTP(totp_secret)
    print("Código TOTP validado com sucesso no servidor.")

    # Decifra o comprovante cifrado
    comprovante_decifrado = decifrar_dados_aes_gcm(chave_sessao, nonce, comprovante_cifrado)
    print(f"Comprovante decifrado: {comprovante_decifrado}")

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
