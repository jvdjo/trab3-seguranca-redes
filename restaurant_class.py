import pyotp
import qrcode
from PIL import Image
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode

# Classe responsável pela autenticação (TOTP e geração de QR Code)
class AuthSystem:
    def __init__(self):
        self.secret = pyotp.random_base32()  # Chave secreta TOTP

    def generate_totp_qrcode(self):
        totp = pyotp.TOTP(self.secret)
        qr_url = totp.provisioning_uri("Usuário", issuer_name="Sistema iFood")
        img = qrcode.make(qr_url)
        img.save("qrcode.png")
        img = Image.open("qrcode.png")
        img.show()
        return totp

    def validate_totp(self, code):
        totp = pyotp.TOTP(self.secret)
        return totp.verify(code)

    def derive_session_key(self, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        session_key = kdf.derive(self.secret.encode())  # Deriva a chave da chave secreta
        return session_key

# Classe responsável pela criptografia (cifrar e decifrar)
class CryptoSystem:
    def __init__(self, auth_system):
        self.auth_system = auth_system
        self.salt = os.urandom(16)  # Salt para derivação de chave

    def encrypt_payment(self, payment):
        session_key = self.auth_system.derive_session_key(self.salt)  # Chave derivada
        iv = os.urandom(12)  # Vetor de inicialização
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(payment.encode()) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    def decrypt_payment(self, iv, ciphertext, tag):
        session_key = self.auth_system.derive_session_key(self.salt)  # Deriva a chave
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

# Classe responsável pelo sistema de pedidos de comida
class FoodOrderSystem:
    def __init__(self, auth_system, crypto_system):
        self.auth_system = auth_system
        self.crypto_system = crypto_system

    def place_order(self):
        # Passo 1: Escolher o prato de comida
        pratos = ['Pizza', 'Hambúrguer', 'Sushi']
        print("Escolha seu prato:")
        for i, prato in enumerate(pratos, 1):
            print(f"{i}. {prato}")
        escolha = int(input("Digite o número do prato: "))
        prato_escolhido = pratos[escolha - 1]
        print(f"Você escolheu {prato_escolhido}.")

        # Passo 2: Solicitar o número de celular do usuário
        celular = input("Digite seu número de celular: ")

        # Passo 3: Geração de QR Code para o TOTP
        totp = self.auth_system.generate_totp_qrcode()
        print("Escaneie o QR Code gerado para configurar o segundo fator de autenticação.")

        # Passo 4: Validação do código TOTP
        code = input("Digite o código TOTP gerado pelo seu app: ")
        if self.auth_system.validate_totp(code):
            print("Autenticação de dois fatores verificada com sucesso!")
        else:
            print("Código TOTP inválido. Processo de pedido cancelado.")
            return

        # Passo 5: Pagamento (simulação)
        pagamento = f"Comprovante de pagamento do prato {prato_escolhido}"
        iv, pagamento_cifrado, tag = self.crypto_system.encrypt_payment(pagamento)
        print("Pagamento cifrado enviado ao sistema.")

        # Passo 6: Decifrar o pagamento no sistema
        pagamento_decifrado = self.crypto_system.decrypt_payment(iv, pagamento_cifrado, tag)
        print(f"Pagamento decifrado: {pagamento_decifrado}")

        # Passo 7: Enviar mensagem cifrada sobre o pedido
        mensagem = f"O seu pedido de {prato_escolhido} chegará em 30 minutos."
        iv_mensagem, mensagem_cifrada, tag_mensagem = self.crypto_system.encrypt_payment(mensagem)
        print("Mensagem cifrada enviada ao usuário.")

        # Passo 8: Decifrar a mensagem no cliente
        mensagem_decifrada = self.crypto_system.decrypt_payment(iv_mensagem, mensagem_cifrada, tag_mensagem)
        print(f"Mensagem decifrada: {mensagem_decifrada}")

# Função principal
def main():
    auth_system = AuthSystem()
    crypto_system = CryptoSystem(auth_system)
    food_order_system = FoodOrderSystem(auth_system, crypto_system)
    
    # Simular o processo de pedido
    food_order_system.place_order()

if __name__ == "__main__":
    main()
