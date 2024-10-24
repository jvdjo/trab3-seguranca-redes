import os
import base64
import qrcode  # Importa a biblioteca para gerar QR Codes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import pyotp
from PIL import Image  # Importa a biblioteca Pillow para manipulação de imagens

class CryptoHelper:
    def __init__(self, password: str):
        self.salt = os.urandom(16)  # Gera um salt aleatório
        self.key = PBKDF2(password, self.salt, dkLen=32)  # Deriva a chave a partir da senha

    def encrypt(self, raw: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(raw)
        return cipher.nonce + tag + ciphertext  # Retorna nonce + tag + ciphertext
    
    def decrypt(self, enc: bytes) -> bytes:
        nonce, tag, ciphertext = enc[:16], enc[16:32], enc[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

class TwoFactorAuth:
    def __init__(self, secret: str):
        self.totp = pyotp.TOTP(secret)  # Inicializa o TOTP com o segredo do usuário

    def validate_totp(self, user_input):
        return self.totp.verify(user_input)  # Verifica o código TOTP

    def get_qr_code(self, username: str):
        # Gera uma URL para o QR code
        uri = self.totp.provisioning_uri(name=username, issuer_name='Food Delivery App')
        # Gera o QR code
        img = qrcode.make(uri)
        img.save("2fa_qr_code.png")  # Salva a imagem do QR code
        print("QR Code gerado e salvo como '2fa_qr_code.png'. Escaneie com seu aplicativo de autenticação.")
        
        # Abre a imagem do QR Code
        self.open_qr_code("2fa_qr_code.png")

    def open_qr_code(self, path: str):
        # Abre a imagem usando Pillow
        img = Image.open(path)
        img.show()  # Exibe a imagem

class User:
    def __init__(self, phone: str, password: str):
        self.phone = phone
        self.crypto_helper = CryptoHelper(password)
        self.secret = pyotp.random_base32()  # Gera um segredo único para TOTP

    def place_order(self, order_details: str):
        encrypted_order = self.crypto_helper.encrypt(order_details.encode())  # Criptografa o pedido
        print("Order placed. Encrypted receipt:", base64.b64encode(encrypted_order).decode())
        return encrypted_order

    def authenticate(self, totp_code: str):
        auth = TwoFactorAuth(self.secret)  # Cria instancia para verificação do TOTP
        return auth.validate_totp(totp_code)  # Valida o TOTP fornecido

    def create_session_key(self, totp_code: str) -> bytes:
        """Gera uma chave de sessão usando o TOTP."""
        return PBKDF2(totp_code, os.urandom(16), dkLen=32)  # Chave derivada do TOTP

class Restaurant:
    def receive_order(self, encrypted_order: bytes):
        print("Order has been successfully received by the restaurant.")

# Simulação do fluxo
if __name__ == "__main__":
    # Entrada do usuário
    phone = input("Digite seu número de telefone: ")
    password = input("Digite sua senha: ")

    # Criando um usuário
    user = User(phone=phone, password=password)
    
    # Gere código QR para TOTP
    auth = TwoFactorAuth(user.secret)
    auth.get_qr_code(phone)  # Usar o número como nome do usuário para QR

    # Escolha do pedido
    print("Menu:")
    print("1. Pizza Margherita")
    print("2. Pasta Carbonara")
    print("3. Burger")
    choice = int(input("Por favor, escolha um prato pelo número (1-3): "))
    
    # Definindo detalhes do pedido com base na escolha
    if choice == 1:
        order_details = "Pizza Margherita"
    elif choice == 2:
        order_details = "Pasta Carbonara"
    elif choice == 3:
        order_details = "Burger"
    else:
        print("Escolha inválida!")
        exit()

    # O usuário faz um pedido
    order = user.place_order(order_details)

    # O usuário deve inserir o código TOTP após escanear o QR Code
    user_input = input("Digite o código TOTP do seu aplicativo autenticador: ").strip()
    if user.authenticate(user_input):
        session_key = user.create_session_key(user_input)  # Cria a chave de sessão
        print("Chave de sessão criada com sucesso.")

        # Simulando o pagamento e criando um comprovante cifrado
        payment_proof = "Comprovante de pagamento para o pedido".encode()  # Comprovante de pagamento
        encrypted_proof = user.crypto_helper.encrypt(payment_proof)  # Usar a instância de CryptoHelper da classe User
        print("Comprovante de pagamento cifrado:", base64.b64encode(encrypted_proof).decode())

        # Decifra o comprovante antes de enviar ao restaurante
        decrypted_proof = user.crypto_helper.decrypt(encrypted_proof)  # Usar a mesma instância
        print("Comprovante de pagamento decifrado:", decrypted_proof.decode())

        # Restaurante recebe o pedido
        restaurant = Restaurant()
        restaurant.receive_order(order)  # Envia o pedido ao restaurante

        # Simulando o envio do horário de entrega
        encrypted_delivery_time = user.crypto_helper.encrypt("Seu pedido chegará em 30 minutos.")
        print("Horário de entrega cifrado enviado ao usuário:", base64.b64encode(encrypted_delivery_time).decode())

        # O usuário decifra a mensagem recebida
        decrypted_delivery_time = user.crypto_helper.decrypt(encrypted_delivery_time)
        print("Mensagem decifrada recebida do restaurante:", decrypted_delivery_time.decode())
    else:
        print("Autenticação falhou.")
