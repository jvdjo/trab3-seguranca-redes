import pyotp
import qrcode
from PIL import Image
import hashlib
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def exibir_menu():
    print("Bem-vindo ao Restaurante Python!")
    print("Escolha um prato:")
    pratos = {
        1: "Pizza",
        2: "Hambúrguer",
        3: "Sushi",
        4: "Salada",
        5: "Lasanha"
    }
    for numero, prato in pratos.items():
        print(f"{numero}. {prato}")
    return pratos


def escolher_prato(pratos):
    while True:
        try:
            escolha = int(input("Digite o número do prato que deseja pedir: "))
            if escolha in pratos:
                return pratos[escolha]
            else:
                print("Escolha inválida, tente novamente.")
        except ValueError:
            print("Por favor, insira um número válido.")


def pedir_celular():
    celular = input("Por favor, insira seu número de celular: ")
    return celular


def gerar_totp_uri(secret, user_email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user_email, issuer_name="Restaurante Python")
    return uri


def gerar_qr_code(uri):
    qr = qrcode.make(uri)
    qr.save("qr_code.png")
    img = Image.open("qr_code.png")
    img.show()


def validar_codigo(totp):
    while True:
        codigo_digitado = input("Digite o código TOTP exibido no aplicativo de autenticação: ")
        if totp.verify(codigo_digitado):
            print("Autenticação de dois fatores bem-sucedida!")
            return codigo_digitado
        else:
            print("Código inválido. Tente novamente.")


def gerar_chave_sessao(senha, salt, iteracoes=100000):
    chave = hashlib.pbkdf2_hmac(
        'sha256',  # Função hash
        senha.encode('utf-8'),  # Senha
        salt,  # Salt
        iteracoes  # Número de iterações
    )
    return chave


def cifrar_dados_aes_gcm(chave_sessao, dados):
    aesgcm = AESGCM(chave_sessao)
    nonce = os.urandom(12)  # Nonce de 96 bits
    dados_cifrados = aesgcm.encrypt(nonce, dados.encode('utf-8'), None)
    return nonce, dados_cifrados


def decifrar_dados_aes_gcm(chave_sessao, nonce, dados_cifrados):
    aesgcm = AESGCM(chave_sessao)
    dados_decifrados = aesgcm.decrypt(nonce, dados_cifrados, None)
    return dados_decifrados.decode('utf-8')


def main():
    pratos = exibir_menu()
    prato_escolhido = escolher_prato(pratos)
    celular = pedir_celular()

    print("\nGerando código TOTP para autenticação de dois fatores...")

    # Gerar segredo TOTP
    secret = pyotp.random_base32()
    user_email = celular + "@restaurante.com"
    uri = gerar_totp_uri(secret, user_email)

    # Gerar QR Code
    print("Escaneie o QR Code com seu aplicativo de autenticação (Google Authenticator, Authy, etc.)")
    gerar_qr_code(uri)

    # Criar o objeto TOTP para validação
    totp = pyotp.TOTP(secret)
    
    # Aguarda o usuário inserir o código
    codigo_totp = validar_codigo(totp)

    # Geração da chave de sessão com PBKDF2
    senha_do_usuario = input("Por favor, insira uma senha para gerar a chave de sessão: ")
    salt = os.urandom(16)  # Geração de um salt aleatório
    chave_sessao = gerar_chave_sessao(senha_do_usuario, salt)

    print("\nResumo do pedido:")
    print(f"Prato: {prato_escolhido}")
    print(f"Celular: {celular}")
    print("Pedido realizado com sucesso!")

    # O usuário realiza o pagamento e cifra o comprovante
    comprovante_pagamento = input("Insira o comprovante de pagamento: ")
    nonce, comprovante_cifrado = cifrar_dados_aes_gcm(chave_sessao, comprovante_pagamento)
    print("Comprovante cifrado e enviado ao sistema.")

    # O sistema decifra o comprovante de pagamento
    comprovante_decifrado = decifrar_dados_aes_gcm(chave_sessao, nonce, comprovante_cifrado)
    print(f"Comprovante decifrado pelo sistema: {comprovante_decifrado}")

    # O sistema envia uma mensagem cifrada para o usuário com o horário de entrega
    horario_entrega = "Seu pedido chegará às 20:00."
    nonce_mensagem, mensagem_cifrada = cifrar_dados_aes_gcm(chave_sessao, horario_entrega)
    print("Mensagem cifrada enviada ao usuário.")

    # O usuário decifra a mensagem
    mensagem_decifrada = decifrar_dados_aes_gcm(chave_sessao, nonce_mensagem, mensagem_cifrada)
    print(f"Mensagem decifrada pelo usuário: {mensagem_decifrada}")


if __name__ == "__main__":
    main()
