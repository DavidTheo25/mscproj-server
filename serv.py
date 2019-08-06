# Currently very experimental, it requires some refactoring to generalize the requests and file exchanges

import socket
import os
from servRequests import Requests
from threading import Thread
# from SocketServer import ThreadingMixIn
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from ast import literal_eval
import json


TCP_IP = ''
TCP_PORT = 9001
BUFFER_SIZE = 1024


class ClientThread(Thread):

    def __init__(self, ip, port, sock):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        self.requests = Requests()
        print(" New thread started for "+ip+":"+str(port))

    @staticmethod
    def decrypt_request(data, private_key_path):
        private_key = RSA.import_key(open(private_key_path).read())
        enc_session_key, nonce, tag, ciphertext = literal_eval(data)

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_req = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("[DEBUG] Decrypted:", decrypted_req.decode("utf-8"))
        return decrypted_req.decode("utf-8")

    @staticmethod
    def decrypt_file(path_to_enc_file, private_user_key):
        file_in = open(path_to_enc_file, "rb")
        private_key_temp = RSA.import_key(private_user_key)
        enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in
                                                   (private_key_temp.size_in_bytes(), 16, 16, -1)]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key_temp)
        session_key = cipher_rsa.decrypt(enc_session_key)
        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        dec_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        os.remove(path_to_enc_file)
        with open(path_to_enc_file, "wb") as dec_f:
            dec_f.write(dec_data)
        return path_to_enc_file

    def receive_request(self):
        data = ""
        while True:
            data_temp = conn.recv(1024)
            if not data_temp:
                print(data)
                break
            if len(data_temp) >= 3:
                if data_temp[-3:] == b"EOR":
                    data += (data_temp[:-3]).decode('utf-8')
                    print(data)
                    break
            data += data_temp.decode('utf-8')
        temp = self.decrypt_request(data, "private1.pem")
        return temp

    @staticmethod
    def receive_file(user, security_token):
        res = {}
        path_to_file = "fr_data/%s" % user
        if not os.path.exists(path_to_file):
            os.makedirs(path_to_file)
        zipfile = "%s/%s.zip" % (path_to_file, user)
        with open(zipfile, 'wb') as f:
            print('file opened')
            wtf = 0
            while True:
                # print('receiving data...')
                data = conn.recv(1024)
                # print('data=', repr(data))
                if not data:
                    break
                if len(data) >= 3:
                    if data[-3:] == b"EOF":
                        f.write(data[:-3])
                        break
                # write data to a file
                f.write(data)
        # extracting security token from the file
        # TODO why not use hash of the file in the future ?
        with open(zipfile, 'rb') as f:
            offset = len(security_token)
            f.seek(-offset, os.SEEK_END)  # Note minus sign
            token_temp = f.read()
            token = token_temp.decode()
        if token == security_token:
            print("[INFO] Valid Token !!")
            # print("[INFO] Decrypting file...")
            # self.decrypt_file(zipfile, "private1.pem")
            # print("[INFO] Done !")
            res["success"] = True
            res["reason"] = "User %s completely registered" % user
        else:
            res["success"] = False
            res["reason"] = "Wrong token"
            print("Wrong token !!")
            os.remove(zipfile)
        return res

    def run(self):
        req = self.receive_request()
        # remove the 3 EOR characters
        result = self.requests.handle(req)
        response = json.dumps(result)
        conn.sendall(response.encode('utf-8'))
        if "success" in result:
            if result["success"]:
                if "token" in result:
                    security_token = result["token"]
                    new_res = self.receive_request()
                    new_result = self.requests.handle(new_res, security_token)
                    if "stop" not in new_result:
                        if "zipfile" in new_result and new_result["success"]:
                            print("[DEBUG] Sending zip file with mail and face recognition data ...")
                            # send file TODO put this in a function to make it cleaner
                            zipfile = new_result["zipfile"]
                            with open(zipfile, "rb") as myfile:
                                buffer = myfile.read(1024)
                                counter = 0
                                while buffer:
                                    counter += 1
                                    conn.send(buffer)
                                    # print('Sent ', repr(buffer))
                                    buffer = myfile.read(1024)
                                # print("counter = ", counter)
                                token_eof = security_token + "EOF"
                                conn.send(token_eof.encode())
                            os.remove(zipfile)
                            print("[DEBUG] Done")
                            print("[DEBUG] Waiting for facial verification... ")
                            facial_rec_data = self.receive_request()
                            facial_rec_response = self.requests.handle(facial_rec_data, security_token)
                            if "success" in facial_rec_response:
                                if facial_rec_response["success"]:
                                    print(["[INFO] Success, sending key ..."])
                                    conn.sendall(facial_rec_response["private_key"])
                                    print("[INFO] key sent !")
                        else:
                            # send error response
                            new_response = json.dumps(new_result)
                            conn.sendall(new_response.encode('utf-8'))
                    new_response = json.dumps(new_result)
                    conn.sendall(new_response.encode('utf-8'))
                if "file_token" in result:
                    new_result = self.receive_file(result["user"], result["file_token"])
                    new_response = json.dumps(new_result)
                    conn.sendall(new_response.encode('utf-8'))
            else:
                print("[INFO] failed: ", result["reason"])


tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((TCP_IP, TCP_PORT))
threads = []

while True:
    tcpsock.listen(5)
    print("Waiting for incoming connections...")
    (conn, (ip, port)) = tcpsock.accept()
    print('Got connection from ', (ip, port))
    newthread = ClientThread(ip, port, conn)
    newthread.start()
    threads.append(newthread)

    for t in threads:
        t.join()
