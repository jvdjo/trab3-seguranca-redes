import pyotp
import qrcode
from PIL import Image
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Usuario:
    def __init__(self, celular):
        self.celular = celular
        self.secret = pyotp.random_base32()
        self.senha = None
        self.chave_sessao = None
        self.totp = pyotp.TOTP(self.secret)

    def gerar_qr_code(self):
        uri = self.totp.provisioning_uri(name=f"{self.celular}@restaurante.com", issuer_name="Restaurante Python")
        qr = qrcode.make(uri)
        qr.save("qr_code.png")
        img = Image.open("qr_code.png")
        img.show()

    def autenticar(self):
        codigo_totp = input("Digite o código TOTP exibido no aplicativo de autenticação: ")
        if self.totp.verify(codigo_totp):
            print("Autenticação de dois fatores bem-sucedida!")
            return True
        else:
            print("Código inválido. Tente novamente.")
            return False

    def definir_senha(self):
        self.senha = input("Por favor, insira uma senha para gerar a chave de sessão: ")
        salt = os.urandom(16)
        self.chave_sessao = self.gerar_chave_sessao(self.senha, salt)
        print("Chave de sessão criada com sucesso.")

    def gerar_chave_sessao(self, senha, salt, iteracoes=100000):
        chave = hashlib.pbkdf2_hmac(
            'sha256', senha.encode('utf-8'), salt, iteracoes
        )
        return chave

    def cifrar_comprovante(self, comprovante):
        aesgcm = AESGCM(self.chave_sessao)
        nonce = os.urandom(12)
        comprovante_cifrado = aesgcm.encrypt(nonce, comprovante.encode('utf-8'), None)
        return nonce, comprovante_cifrado

    def decifrar_mensagem(self, nonce, mensagem_cifrada):
        aesgcm = AESGCM(self.chave_sessao)
        mensagem_decifrada = aesgcm.decrypt(nonce, mensagem_cifrada, None)
        return mensagem_decifrada.decode('utf-8')


class Sistema:
    def __init__(self):
        self.chave_sessao = None

    def validar_usuario(self, usuario):
        while not usuario.autenticar():
            pass
        usuario.definir_senha()
        self.chave_sessao = usuario.chave_sessao

    def decifrar_comprovante(self, nonce, comprovante_cifrado):
        aesgcm = AESGCM(self.chave_sessao)
        comprovante_decifrado = aesgcm.decrypt(nonce, comprovante_cifrado, None)
        print(f"Comprovante decifrado: {comprovante_decifrado.decode('utf-8')}")

    def enviar_mensagem(self, mensagem):
        aesgcm = AESGCM(self.chave_sessao)
        nonce = os.urandom(12)
        mensagem_cifrada = aesgcm.encrypt(nonce, mensagem.encode('utf-8'), None)
        return nonce, mensagem_cifrada


def main():
    # Usuário realiza o pedido e autenticação
    celular = input("Insira seu número de celular: ")
    usuario = Usuario(celular)
    sistema = Sistema()

    print("Gerando QR Code para 2FA...")
    usuario.gerar_qr_code()

    # Autenticação e geração de chave de sessão
    sistema.validar_usuario(usuario)

    # Usuário insere comprovante de pagamento e cifra
    comprovante = input("Insira o comprovante de pagamento: ")
    nonce_comprovante, comprovante_cifrado = usuario.cifrar_comprovante(comprovante)
    print("Comprovante cifrado e enviado para o sistema.")

    # Sistema decifra o comprovante
    sistema.decifrar_comprovante(nonce_comprovante, comprovante_cifrado)

    # Sistema envia mensagem cifrada
    mensagem = "Seu pedido chegará às 20:00."
    nonce_mensagem, mensagem_cifrada = sistema.enviar_mensagem(mensagem)
    print("Mensagem cifrada enviada ao usuário.")

    # Usuário decifra a mensagem
    mensagem_decifrada = usuario.decifrar_mensagem(nonce_mensagem, mensagem_cifrada)
    print(f"Mensagem decifrada pelo usuário: {mensagem_decifrada}")


if __name__ == "__main__":
    main()
