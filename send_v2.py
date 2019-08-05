import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def encrypt_request(request, public_key_path):
    encoded_req = request.encode('utf-8')
    public_key = RSA.import_key(open(public_key_path).read())
    session_key = get_random_bytes(16)

    # encrypt session key with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # encrypt data with aes session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(encoded_req)

    return str((enc_session_key, cipher_aes.nonce, tag, cipher_text)).encode()


TCP_IP = 'localhost'
# TCP_IP = "192.168.56.103"
TCP_PORT = 9001
BUFFER_SIZE = 1024

public_key_p = "public1.pem"

email = input("email address: ")
subject = input("Subject: ")
content = input("Content: ")
# email = "toplexil40@gmail.com"
# subject = "alors ça chiffre ?"
# content = "trop cooool"
req = "send,%s,%s,%s" % (email, subject, content)

req_to_send = encrypt_request(req, public_key_p)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((TCP_IP, TCP_PORT))
    # s.sendall(req.encode('utf-8'))
    s.sendall(req_to_send)
    s.sendall(b"EOR")
    print("[INFO] request sent")
    data = s.recv(BUFFER_SIZE)
print('Received', repr(data))


print('Sent request')
# s.close()
print('connection closed')
