from userData import UserData
from sendMail import SendMail
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from pathlib import Path
from Crypto.PublicKey import RSA
import os
import shutil
import hashlib
import random
import string
import zipfile


class Requests:

    def __init__(self):
        self.actions = {"register": self.request_register, "send": self.request_send_email, "login": self.request_login,
                        "get2": self.request_get_email, "get_key": self.request_get_key, "stop": self.request_stop,
                        "delete": self.request_delete}
        self.ud = UserData("user_data.csv")
        self.sm = SendMail()

    def handle(self, req, token=None):
        request = req.split(",")
        action = request[0]
        params = request[1:]
        if token:
            params.append(token)
        return self.actions[action](params)

    # checks if a user already have a pair of keys
    @staticmethod
    def has_keys(user):
        path_to_private = "keys/%s/private.pem" % user
        path_to_public = "keys/%s/public.pem" % user
        return os.path.exists(path_to_private) and os.path.exists(path_to_public)

    # create a pair of RSA keys for a user
    @staticmethod
    def gen_keys(user):
        path_to_keys = "keys/%s" % user
        path_to_private = "keys/%s/private.pem" % user
        path_to_public = "keys/%s/public.pem" % user
        if not os.path.exists(path_to_keys):
            os.makedirs(path_to_keys)
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open(path_to_private, "wb")
        file_out.write(private_key)
        public_key = key.publickey().export_key()
        file_out = open(path_to_public, "wb")
        file_out.write(public_key)
        print("[INFO] RSA keys generated !")

    # Overwrites a file with an eencrypted version
    @staticmethod
    def encrypt_file(file_path, public_key_path):
        data = open(file_path).read().encode("utf-8")
        enc_file_path = file_path
        file_out = open(enc_file_path, "wb")
        recipient_key = RSA.import_key(open(public_key_path).read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        file_out.close()
        return enc_file_path

    @staticmethod
    def request_stop(params):
        return {"success": True, "stop": True, "Reason": "stop requested"}

    # params[0] should be email address and params[1] should be pswd
    def request_register(self, params):
        res = {}
        token_length = 16
        if len(params) == 2:
            res = self.ud.appendfile(params[0], params[1])
            if not self.has_keys(params[0]):
                self.gen_keys(params[0])
            res["file_token"] = self.generate_token(token_length)
            # res["token_length"] = token_length
            res["user"] = params[0]
        else:
            res["success"] = False
            res["reason"] = "register request should have 2 arguments: email address and password"
        return res

    # Removes all data concerning an user
    def request_delete(self, params):
        res = {}
        if len(params) == 2:
            if self.ud.authorize(params[0], params[1]):
                print("[INFO] Deleting data of user %s ..." % params[0])
                for folder in ("fr_data", "keys", "mail"):
                    folder_to_remove = folder + "/" + params[0]
                    if os.path.exists(folder_to_remove):
                        shutil.rmtree(folder_to_remove)
                self.ud.remove_entry(params[0])
                print("[INFO] Done !")
                res["success"] = True
            else:
                res["success"] = False
                res["reason"] = "Invalid email address or password"
        else:
            res["success"] = False
            res["reason"] = "Invalid number of parameters, delete requires an email address and password"
        return res

    # params[0] should be recipient, params[1] subject and params[2] content
    def request_send_email(self, params):
        res = {}
        if len(params) == 3:
            recipient = params[0]
            recipient_hash = hashlib.sha256(recipient.encode()).hexdigest()
            subject = params[1]
            content = params[2]
            # TODO maybe put these in a file ...
            default_message = "You received a new secret message\nDownload the receiving app to see it"
            default_subject = "New secret message"
            path_to_mail = "mail/" + recipient_hash

            # Create mail folder if it does not already exists
            if not os.path.exists(path_to_mail):
                os.makedirs(path_to_mail)
            # Assign an id to the email
            mail_id = 0
            list_dir = os.listdir(path_to_mail)
            while str(mail_id) in list_dir:
                mail_id += 1
            mail_id = str(mail_id)

            path_to_mail_id = path_to_mail + "/" + mail_id
            with open(path_to_mail_id, 'wb') as f:
                file_content = subject + "\n" + content
                f.write(file_content.encode('utf-8'))

            # send notification to recipient
            raw_msg = self.sm.create_message(self.sm.SENDER, recipient, default_subject, default_message)
            message = self.sm.send_message(self.sm.service, "me", raw_msg)
            if message["labelIds"][0] == "SENT":
                if not self.has_keys(recipient_hash):
                    self.gen_keys(recipient_hash)
                path_to_key = "keys/%s/public.pem" % recipient_hash
                # encrypt email with recipient's public key
                self.encrypt_file(path_to_mail_id, path_to_key)
                res["success"] = True
            else:
                res["success"] = False
                os.remove(path_to_mail_id)

            res["reason"] = "Message " + message["labelIds"][0] + " Id: " + message["id"]
        else:
            res["success"] = False
            res["reason"] = "send request should have 3 arguments: recipient email address, subject and content"
        return res

    # TODO add pswd verification
    # this should be the "final" get email function (at least in the unencrypted version of the project)
    # params[0] should be recipient, params[1] received token, params[2] security token
    @staticmethod
    def request_get_email(params):
        res = {}
        if len(params) == 3:
            if params[1] == params[2]:
                recipient = params[0]
                path_to_mail = "mail/" + recipient
                path_to_face_model = "fr_data/" + recipient + "/" + recipient + ".zip"
                if os.path.exists(path_to_face_model):
                    if os.path.exists(path_to_mail):
                        res["success"] = True
                        # zip all the mail and the face recognition data in the same archive
                        # this is not secure at all, in version 2 messages will be encrypted or sent separately
                        zipname = "%s_fr+mail.zip" % recipient
                        with zipfile.ZipFile(zipname, 'w') as output_zip:
                            for file in os.listdir(path_to_mail):
                                file_path = os.path.join(path_to_mail, file)
                                print("[DEBUG] ", file_path)
                                output_zip.write(file_path, file)
                                # TODO delete messages after they've been sent (after testing)
                                # os.remove(file_path)
                            output_zip.write(path_to_face_model, "fr_data.zip")
                        res["zipfile"] = zipname
                    else:
                        res["success"] = False
                        res["reason"] = "No message folder"
                else:
                    res["success"] = False
                    res["reason"] = "No face recognition data, registration might not be complete"
            else:
                res["success"] = False
                res["reason"] = "Invalid security token"
        else:
            res["success"] = False
            res["reason"] = "Invalid number of parameters"
        return res

    # params[0] is email address and params[1] is password
    def request_login(self, params):
        res = {}
        if len(params) == 2:
            if self.ud.authorize(params[0], params[1]):
                recipient = params[0]
                res["success"] = True
                path_to_mail = "mail/" + recipient
                if not os.path.exists(path_to_mail):
                    nb_of_unread_message = 0
                else:
                    nb_of_unread_message = len(os.listdir(path_to_mail))
                res["reason"] = "you have " + str(nb_of_unread_message) + " unread email(s)"
                # res["token"] = str(get_random_bytes(16))
                res["token"] = self.generate_token(16)
                print("token: ", res["token"])
            else:
                res["success"] = False
                res["reason"] = "Wrong email or password"
        else:
            res["success"] = False
            res["reason"] = "login request should have 2 arguments: email address and password"
        return res

    # params[0] should be email address, params[1] should be user's password, params[2] should be received token
    # params[3] should be security token
    def request_get_key(self, params):
        res = {}
        if len(params) == 4:
            email = params[0]
            pswd = params[1]
            received_token = params[2]
            security_token = params[3]
            if received_token == security_token:
                if self.ud.authorize(email, pswd):
                    path_to_key = "keys/%s/private.pem" % email
                    res["success"] = True
                    res["private_key"] = open(path_to_key, "rb").read()
                    res["reason"] = ""
                    # TODO activate key changing after testing is over ...
                    # print("[INFO] changing keys for this user")
                    # self.gen_keys(email)
                else:
                    res["success"] = False
                    res["reason"] = "Wrong password or email address"
            else:
                res["success"] = False
                res["reason"] = "Wrong security token"
        return res

    @staticmethod
    def generate_token(length=16):
        # Generate a random string of letters, digits and special characters
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(length))
