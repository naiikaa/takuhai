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
        self.login_attempts = dict()
        self.esks, self.ePKs = sample_curve_key_pair()
        self.user_to_AEK_SK = {}

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
        print(f"Key confirmation for {username}")
        K_s, K_c = get_key_conf_key_pair(self.user_to_AEK_SK[client_socket])
        mac_c2 = hmac_sign(K_c,b"Client KC").hex()
        if mac_c == mac_c2:
            print(f"Key confirmation successful for {username}")
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
            K_s, K_c = get_key_conf_key_pair(self.user_to_AEK_SK[client_socket])
            mac_s = hmac_sign(K_s,b"Server KC").hex()
            payload = {"type": "login_response", "h(pw)_alpha_salt": h_pw_alpha_salt.hex(), "enc_client_key_info": enc_client_key_info, "ePKs": self.ePKs.to_string().hex(), "mac_s": mac_s}
            client_socket.sendall(json.dumps(payload).encode('utf-8'))
        else:  

            client_socket.sendall(b"User not found. Register first!")

    def server_handle_message(msg,client_socket,target_socket):
        if user_exists(msg['target']):
            target_socket.sendall(json.dumps(msg).encode('utf-8'))
        
        
        

    server_handler = {
        'login': handle_login,
        'register': handle_register,
        'message': server_handle_message,
        'key_confirmation': handle_key_confirmation,
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
        print(f"Connection closed with {client_socket.getpeername()}")

if __name__ == "__main__":
    server = Server()
    server.start()