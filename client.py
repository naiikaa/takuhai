import socket
import ssl
import threading
import json
import time
import os
import traceback

from utils.cryptographic_utils import *
from utils.constants import *



class Client:
    def __init__(self):
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(CERT_PATH)
        self.ssock = None
        self.sock = None
        self.eskc, self.ePKc = sample_curve_key_pair()
        self.last_alpha = None
        self.rw = None
        self.rw_key = None
        self.key_info = None
        self.AEK_SK = None

     
        while True:
            try:
                self.connect_to_server()
                break
            except Exception as e:
                print(f"Failed to connect to server.")
                print("Retrying in 2 seconds...")
                time.sleep(2)

    def client_handle_message(self,msg):
        print(f"{msg['sender']}: {msg['message']}")

    def handle_system_message(self,msg):
        print(f"System: {msg['message']}")
        if msg['message'] == "User registered successfully. Try logging in.":
            self.login()

        if msg['message'] == "User already exists. Try logging in.":
            self.login()
    

    def handle_login_response(self,msg):
        print("Handling login response")
        h_pw_alpha_salt = point_from_value(bytes.fromhex(msg['h(pw)_alpha_salt']))
        enc_client_key_info = msg['enc_client_key_info']
        h_pw_salt = inverse(self.last_alpha) * h_pw_alpha_salt
        self.rw = hasher(self.password.encode() + h_pw_salt.to_bytes()).digest()
        self.rw_key = hkdf_extract(None, self.rw)
        self.key_info = json.loads(aes_gcm_decrypt(self.rw_key, bytes.fromhex(enc_client_key_info['iv']), bytes.fromhex(enc_client_key_info['cipher']),b"", bytes.fromhex(enc_client_key_info['tag'])))

        ePKs = msg['ePKs']
        ePKs = VerifyingKey.from_string(bytes.fromhex(ePKs),curve=CURVE)
        self.AEK_SK = HMQV_KClient(self.username, ePKs, self.ePKc, self.eskc, self.key_info)
        K_s, K_c = get_key_conf_key_pair(self.AEK_SK)
        mac_s = msg['mac_s']
        mac_s2 = hmac_sign(K_s, b"Server KC").hex()
        if mac_s == mac_s2:
            print("Key confirmation successful")
            mac_c = hmac_sign(K_c, b"Client KC")
            payload = {"type": "key_confirmation","username":self.username ,"mac_c": mac_c.hex()}
            message = json.dumps(payload)
            self.ssock.sendall(message.encode('utf-8'))

    client_handler = {
        'message' : client_handle_message,
        'system_message' : handle_system_message,
        'login_response' : handle_login_response,

    }

    def register(self):
        print("Registering user...")
        payload = {"type": "register", "username": self.username, "password": self.password}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    
    def login(self):
        print("Logging in...")
        self.last_alpha = int.from_bytes(os.urandom(32),'big') % n
        h_pw_alpha = (hash_to_curve(self.password.encode())*self.last_alpha).to_bytes()
        payload = {"type": "login", "username": self.username, "h(pw)_alpha": h_pw_alpha.hex(), "ePKc": self.ePKc.to_string().hex()}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))


    def connect_to_server(self):
        try:
            self.sock = socket.create_connection(SERVER_ADDRESS)
            self.ssock = self.context.wrap_socket(self.sock, server_hostname='localhost')
            #sending thread
            #self.send_thread = threading.Thread(target=self.send_messages)
            #self.send_thread.start()
            #listening thread
            self.listen_thread = threading.Thread(target=self.receive_message)
            self.listen_thread.start()    

            self.register()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.ssock.close()

    def receive_message(self):
        while True:
            try:
                data = self.ssock.recv(MSG_SIZE).decode('utf-8')
                if not data:
                   break

                msg = json.loads(data)
                type = msg['type']
                self.client_handler[type](self,msg)

            except Exception as e:
                traceback.print_exc()
                


if __name__ == "__main__":
    Client()