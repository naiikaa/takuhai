import socket
import ssl
import threading
import hashlib
import os
import json
import traceback
from utils.cryptographic_utils import sample_curve_key_pair
from utils.constants import * 
from utils.database_utils import *
from utils.cryptographic_utils import *

class Server:
    def __init__(self):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=CERT_PATH, keyfile=CERT_KEY_PATH)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(SERVER_ADDRESS)
        self.sock.listen(5)
        self.ssock = self.context.wrap_socket(self.sock, server_side=True)
        print(f"Server listening on {SERVER_ADDRESS}")
        self.client_threads = []
        self.socket_to_user = {}
        self.user_to_socket = {}
        self.esks, self.ePKs = sample_curve_key_pair()
        self.user_to_AEK_SK = {}
        self.messages_for_users = {}

        #check if database exists and create if not
        if not os.path.exists(DATABASE_PATH):
            with open(DATABASE_PATH,"w") as db:
                pass

    
    def handle_register(self,client_socket,msg):
        username = msg['username']
        print(f"Registering user {username}")
        if user_exists(username):
            self.send_server_message(client_socket,"User already exists. Try logging in.")
        else:
            register_user(msg)
            self.send_server_message(client_socket,"User registered successfully. Try logging in.")
        print(f"Registered user {username}") 

    def handle_key_confirmation(self,client_socket,msg):
        username = msg['username']
        print(f"Key confirmation for {username}")
        mac_c = msg['mac_c']
        K_s, K_c = get_key_conf_key_pair(self.user_to_AEK_SK[client_socket])
        mac_c2 = hmac_sign(K_c,b"Client KC").hex()
        if mac_c == mac_c2:
            print(f"Key confirmation successful for {username}")
            self.send_waiting_messages(username)
        else:
            print(f"Key confirmation failed for {username}")


    def handle_login(self, client_socket,msg):
        username = msg['username']  
        print(f"Logging in user {username}")         
        if user_exists(username):
            h_pw_alpha = msg['h(pw)_alpha']
            h_pw_alpha = point_from_value(bytes.fromhex(h_pw_alpha))
            salt = get_user_salt(username)
            h_pw_alpha_s = h_pw_alpha * salt
            h_pw_alpha_salt = h_pw_alpha_s.to_bytes()
            enc_client_key_info = get_user_enc_client_key_info(username)
            ePKc = VerifyingKey.from_string(bytes.fromhex(msg['ePKc']),curve=CURVE)
            lPKc, lsks, lPKs = get_user_keys(username)
            self.user_to_AEK_SK[client_socket] = HMQV_KServer(ePKc,self.ePKs,self.esks,lPKc,lsks,lPKs,username)
            self.socket_to_user[client_socket] = username
            self.user_to_socket[username] = client_socket
            K_s, K_c = get_key_conf_key_pair(self.user_to_AEK_SK[client_socket])
            mac_s = hmac_sign(K_s,b"Server KC").hex()
            payload = {"type": "login_response", "h(pw)_alpha_salt": h_pw_alpha_salt.hex(), "enc_client_key_info": enc_client_key_info, "ePKs": self.ePKs.to_string().hex(), "mac_s": mac_s}
            client_socket.sendall(json.dumps(payload).encode('utf-8'))
        else:  

            client_socket.sendall(b"User not found. Register first!")

    def send_waiting_messages(self,username):
        print(f"Sending waiting messages for {username}")
        if username in self.messages_for_users:
            for msg in self.messages_for_users[username]:
                target_socket = self.user_to_socket[username]
                self.server_handle_message(msg,target_socket)
            self.messages_for_users.pop(username)

    def server_handle_message(self,msg,target_socket):
        iv, cipher,tag = aes_gcm_encrypt(self.user_to_AEK_SK[target_socket],json.dumps(msg),b"")
        msg = {"type":"encrypted","iv":iv.hex(),"cipher":cipher.hex(),"tag":tag.hex()}
        target_socket.sendall(json.dumps(msg).encode('utf-8'))
        

    def handle_encrypted_message(self,client_socket,msg):
        iv = bytes.fromhex(msg['iv'])
        cipher = bytes.fromhex(msg['cipher'])
        tag = bytes.fromhex(msg['tag'])
        associated_data = b""
        plaintext = aes_gcm_decrypt(self.user_to_AEK_SK[client_socket],iv,cipher,associated_data,tag)
        print(f"Decrypted message: {plaintext}")
        data = json.loads(plaintext)

        if data['type'] == 'x3dh':
            store_x3dh(data)
        if data['type'] == 'message':
            target = data['target']
            msg = data['message']

            if target not in self.user_to_socket:
                print(f"User {target} not online. Storing message in queue")
                if target not in self.messages_for_users:
                    self.messages_for_users[target] = []
                self.messages_for_users[target].append(msg)
                print(f"Message for {target} stored in queue")
            else:
                target_socket = self.user_to_socket[target]
                print(f"Forwading message to {target}")
                self.server_handle_message(msg,target_socket)

    def handle_get_x3dh_keybundle(self,client_socket,msg):
        username = msg['username']
        target = msg['target']
        print(f"Getting X3DH {target} keybundle for {username}")
        payload = {"type":"get_x3dh_keybundle","target":target,"keybundle":get_x3dh_keybundle(target)}
        client_socket.sendall(json.dumps(payload).encode('utf-8'))
        

    server_handler = {
        'login': handle_login,
        'register': handle_register,
        'key_confirmation': handle_key_confirmation,
        'encrypted': handle_encrypted_message,
        'get_x3dh_keybundle': handle_get_x3dh_keybundle
    }


    def send_server_message(self,client_socket,message):
        client_socket.sendall(json.dumps({"type":"system_message","message":message}).encode('utf-8'))

        
    def start(self):
        while True:
            client_socket, client_address = self.ssock.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_connections, args=(client_socket,))
            client_thread.start()
            self.client_threads.append(client_thread)

    def handle_connections(self, client_socket):
        while True:
            try:
                data = client_socket.recv(MSG_SIZE).decode('utf-8')
                if not data:
                    self.clean_up(client_socket)
                    break
                msg = json.loads(data)
                type = msg['type']

                if type == 'AKE':
                    self.server_handler[type](self,client_socket,msg)
                elif type == 'key_confirmation':
                    self.server_handler[type](self,client_socket,msg)
                else:
                    self.server_handler[type](self,client_socket,msg)

            except Exception as e:
                traceback.print_exc()
                break
    
    def clean_up(self, client_socket):

        self.user_to_AEK_SK.pop(client_socket)
        client_socket.close()
        self.client_threads.remove(threading.current_thread())
        print(f"Connection closed with {self.socket_to_user[client_socket]}")
        self.socket_to_user.pop(client_socket)

if __name__ == "__main__":
    server = Server()
    server.start()