import time, requests, base64, json, base64
from jose import jws
from cryptography.hazmat.primitives import serialization
from age.keys.rsa import RSAPrivateKey
from age.primitives.rsa_oaep import rsa_decrypt

# Import config.json
with open("config.json", "r") as f:
    config = json.load(f)

# Load private_key
with open("example_private", "rb") as key_file:
    private_key_global = serialization.load_pem_private_key(key_file.read(), password=None)

def generateJWT():
    apiKey = config["apiKey"]
    payload = {"api_key": apiKey, "ts": int(time.time())}
    key = private_key_global.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    
    signed = "Bearer " + str(jws.sign(payload, key, algorithm='RS256'))
    return signed

def get_card(card_id):
    getEncrypted = False
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-card-number"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": config["publicKey"]
        }

        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_card_number"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CardNumber MESSAGE-----", "").replace("-----END CardNumber MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(e)
            pass

    base64_message = bytes(base64.b64decode(bytes(encrypted, encoding='iso-8859-1')).decode('iso-8859-1'), encoding='iso-8859-1')

    private_key = RSAPrivateKey.from_pem(private_key_global)

    decrypted = rsa_decrypt(private_key, b"CardNumber", base64_message).decode()
    return decrypted

def get_cvv(card_id):
    getEncrypted = False
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-cvv2"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": config["publicKey"]
            }
        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_cvv2"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CVV2 MESSAGE-----", "").replace("-----END CVV2 MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(e)
            pass

    base64_message = bytes(base64.b64decode(bytes(encrypted, encoding='iso-8859-1')).decode('iso-8859-1'), encoding='iso-8859-1')

    private_key = RSAPrivateKey.from_pem(private_key_global)

    decrypted = rsa_decrypt(private_key, b"CVV2", base64_message).decode()
    return decrypted

def get_all_cards(numberOfCards):
    i = 0
    while i < int(numberOfCards):
        url = f"https://api-frontend.wallester.com/v1/product-cards?from_record={i}&records_count={i+100}"
        headers = {
                "Authorization": generateJWT()
            }
        try:
            data = requests.get(url, headers=headers).json()
            print(data)
        except Exception as e:
            print(e)
            pass
        i = i + 100

def create_card():
    getEncryted = False
    while getEncryted == False:
        try:
            url = "https://api-frontend.wallester.com/v1/cards"

            headers = {
                "Authorization": generateJWT()
            }

            payload = {
                "account_id": config["accountId"],
                "type": "Virtual",
                "name": config["firstName"],
                "3d_secure_settings": {
                    "language_code": "ENG",
                    "mobile": config["phone"],
                    "password": config["password"],
                    "type": "SMSOTPAndStaticPassword"
                }
            }

            data = requests.post(url, headers=headers, json=payload).json()
            card_id = data["card"]["id"]
            cardExpiry = data["card"]["expiry_date"]
            getEncryted = True
        except Exception as e:
            print(e)
            pass

    cardNumber = get_card(card_id)
    cardCvv = get_cvv(card_id)
    print(str(cardNumber)+"      "+str(cardExpiry)+"      "+str(cardCvv)+"      "+str(card_id))
    with open('card.txt', 'a') as f:
        f.write(f"{cardNumber},{cardExpiry},{cardCvv},{card_id}")
        f.write('\n')
        f.close()

numberOfCards = int(input("How many cards do you want to create? "))

i = 0
while i < numberOfCards:
    create_card()
    i = i + 1
