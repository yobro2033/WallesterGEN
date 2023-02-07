import time, requests, base64
from jose import jws
from cryptography.hazmat.primitives import serialization
import os, base64
from age.keys.rsa import RSAPrivateKey, RSAPublicKey
from age.primitives.rsa_oaep import rsa_decrypt, rsa_encrypt

## Need api key within this function, private key must be same as the one used to assign to api key
def generateJWT():
    private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----"""
    apiKey = "" # API KEY HERE
    payload = {"api_key": apiKey, "ts": int(time.time())}
    with open("/Users/quocvietphan/Desktop/example_private", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    key = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    signed = "Bearer " + str(jws.sign(payload, key, algorithm='RS256'))
    return signed

## public/private key required here
def get_card(card_id):
    getEncrypted = False
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-card-number"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF0aDI4YjhjVGkrK2lwcUFlaVZGaTNaang3RE94bU8yMUY4ZmdTWDB3ZHlycW1tZUFsa21kSE9sSmw0R2k4bTV6enZoSFF4Q3ZNYzR3Q2pwWXY3L01XSFdzUXpTZ25YY1MyRXArMDhQeThUbVd0cFVsTWd5ei9QYU8rRXgvbTlENXZXS3VLUDl0K2xiZzU0akFUUlFNNDRhWFV2Vm00K1hoR2FvbnZZSFdNbC9FV3MwMzVVSWFDWGxrcS9BdmYvei8yajgrOU95UFFNcUhGY1dQK2taUUd4T3p2NjI1OHdybitIampUMjZJSDZCbytTS0laY2tlN3QvQWtLKzlmemErMlVENjhTR3oyMC91SFFzWmN1blQ1YXJXZkhmZEU3UFp6cWFhWlNpcGxURW1xeUg4VjJ3c1ZqVEVQa05WL3BwcnlQczcxTlNqeXZyV3ZiYmZSbFN0ODdFMElWdVIxK2FBRWx5bmZMOWlWYjhhNVNIRFVtL1J3YVpxYXpFT3pmTDNpKzFiQjJOckRSdm9RczRjS0xYa1Y0TFF5WmRPUnNlRFI1QUt6VmVuQUJMTmUvMVV5UGl6SllNZHNDdG1iMkphWEJ5cVgwMlRYK2xJQ3RyNXBPNlFMbklOdjBzNWkwbkY2MWlnUXdMc2ptNHdGR3ppRCt5QUozQUl3dStDS3YrVmlmZkNUWFRGdEpiRXBub3loaHBaTTV4ZTByeWxPSUhKSzFlVWtROGRwODR6Wi93ZEY2cDR6cDFFMkpCWXhzSm5BdllEbVE4MkIzNUkrbGIyMThiS1l1Yzl6em5KSkFTT1VIbUdROE9oOU9wQXdTV3RnNEJpVm1LQXJPUEpXSmlrSWY4bE0rNmdVbmNqR2xzTjNKamtxUTFVekZXM2FGcWlDaGd1U3dqR1g2c0NBd0VBQVE9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K"
            }
        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_card_number"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CardNumber MESSAGE-----", "").replace("-----END CardNumber MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(data)
            print(e)
            continue

    TEST_PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
    label = b"CardNumber"
    encrypted = bytes(encrypted, encoding='iso-8859-1')
    base64_bytes = base64.b64decode(encrypted)
    base64_message = base64_bytes.decode('iso-8859-1')
    base64_message = bytes(base64_message, encoding='iso-8859-1')

    private_key = RSAPrivateKey.from_pem(TEST_PRIVATE_KEY)

    decrypted = str(rsa_decrypt(private_key, label, base64_message)).replace("b'", "").replace("'", "")
    return decrypted

## public/private key required here
def get_cvv(card_id):
    getEncrypted = False
    while getEncrypted == False:
        url = f"https://api-frontend.wallester.com/v1/cards/{card_id}/encrypted-cvv2"
        headers = {
                "Authorization": generateJWT()
            }

        payload = {
                "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF0aDI4YjhjVGkrK2lwcUFlaVZGaTNaang3RE94bU8yMUY4ZmdTWDB3ZHlycW1tZUFsa21kSE9sSmw0R2k4bTV6enZoSFF4Q3ZNYzR3Q2pwWXY3L01XSFdzUXpTZ25YY1MyRXArMDhQeThUbVd0cFVsTWd5ei9QYU8rRXgvbTlENXZXS3VLUDl0K2xiZzU0akFUUlFNNDRhWFV2Vm00K1hoR2FvbnZZSFdNbC9FV3MwMzVVSWFDWGxrcS9BdmYvei8yajgrOU95UFFNcUhGY1dQK2taUUd4T3p2NjI1OHdybitIampUMjZJSDZCbytTS0laY2tlN3QvQWtLKzlmemErMlVENjhTR3oyMC91SFFzWmN1blQ1YXJXZkhmZEU3UFp6cWFhWlNpcGxURW1xeUg4VjJ3c1ZqVEVQa05WL3BwcnlQczcxTlNqeXZyV3ZiYmZSbFN0ODdFMElWdVIxK2FBRWx5bmZMOWlWYjhhNVNIRFVtL1J3YVpxYXpFT3pmTDNpKzFiQjJOckRSdm9RczRjS0xYa1Y0TFF5WmRPUnNlRFI1QUt6VmVuQUJMTmUvMVV5UGl6SllNZHNDdG1iMkphWEJ5cVgwMlRYK2xJQ3RyNXBPNlFMbklOdjBzNWkwbkY2MWlnUXdMc2ptNHdGR3ppRCt5QUozQUl3dStDS3YrVmlmZkNUWFRGdEpiRXBub3loaHBaTTV4ZTByeWxPSUhKSzFlVWtROGRwODR6Wi93ZEY2cDR6cDFFMkpCWXhzSm5BdllEbVE4MkIzNUkrbGIyMThiS1l1Yzl6em5KSkFTT1VIbUdROE9oOU9wQXdTV3RnNEJpVm1LQXJPUEpXSmlrSWY4bE0rNmdVbmNqR2xzTjNKamtxUTFVekZXM2FGcWlDaGd1U3dqR1g2c0NBd0VBQVE9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K"
            }
        try:
            data = requests.post(url, headers=headers, json=payload).json()
            encryptedCard = data["encrypted_cvv2"]
            encrypted = encryptedCard.replace("\n", "").replace("-----BEGIN CVV2 MESSAGE-----", "").replace("-----END CVV2 MESSAGE-----", "")
            getEncrypted = True
        except Exception as e:
            print(data)
            print(e)
            continue

    TEST_PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

    label = b"CVV2"
    encrypted = bytes(encrypted, encoding='iso-8859-1')
    base64_bytes = base64.b64decode(encrypted)
    base64_message = base64_bytes.decode('iso-8859-1')
    base64_message = bytes(base64_message, encoding='iso-8859-1')

    private_key = RSAPrivateKey.from_pem(TEST_PRIVATE_KEY)

    decrypted = str(rsa_decrypt(private_key, label, base64_message)).replace("b'", "").replace("'", "")
    return decrypted

def get_all_cards():
    getEncrypted = False
    while getEncrypted == False:
        url = "https://api-frontend.wallester.com/v1/product-cards?from_record=0&records_count=100"
        headers = {
                "Authorization": generateJWT()
            }
        try:
            data = requests.get(url, headers=headers).json()
            print(data)
            getEncrypted = True
        except Exception as e:
            print(data)
            print(e)
            continue

## Account id key required here
def create_card():
    getEncryted = False
    while getEncryted == False:
        try:
            url = "https://api-frontend.wallester.com/v1/cards"

            headers = {
                "Authorization": generateJWT()
            }

            payload = {
            "account_id": "", #####ACCOUNTIDHERE,
            "type": "Virtual",
            "name": "Viet",
            "3d_secure_settings": {
                "language_code": "ENG",
                "mobile": "+447587745964",
                "password": "ABCDEfgh1234!",
                "type": "SMSOTPAndStaticPassword"
            }
            }

            data = requests.post(url, headers=headers, json=payload).json()
            card_id = data["card"]["id"]
            cardExpiry = data["card"]["expiry_date"]
            getEncryted = True
        except Exception as e:
            print(data)
            print(e)
            continue

    cardNumber = get_card(card_id)
    cardCvv = get_cvv(card_id)
    print(str(cardNumber)+":"+str(cardExpiry)+":"+str(cardCvv)+"||||"+str(card_id))

#get_all_cards()
#time.sleep(500)

i = 0
while i < 267:
    create_card()
    i = i + 1