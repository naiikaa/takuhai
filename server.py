import socket
import ssl
import threading
import hashlib
import os
import json
from utils.cryptographic_utils import sample_curve_key_pair
from utils.msg_handler import server_handler
from utils.constants import * 
from utils.database_utils import *

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
        if not os.path.exists(self.database_path):
            with open(self.database_path,"w") as db:
                pass

    
    def handle_register(self,client_socket,msg):
        username = msg['username']

        if user_exists(username):
            self.send_server_message(client_socket,"User already exists. Try logging in.")
        else:
            register_user(msg)
            self.send_server_message(client_socket,"User registered successfully. Try logging in.")
        print(f"Registered user {username}") 



    def handle_AKE(client_socket,msg,ePKs,esks,user_to_AEK_SK):
        username = msg['username']
        ePKc = msg['ePKc']
        ePKc = VerifyingKey.from_string(bytes.fromhex(ePKc),curve=CURVE)
        payload = {"type":"AKE_reaction","ePKs":ePKs.to_string().hex()}
        client_socket.sendall(json.dumps(payload).encode('utf-8'))
        lPKc, lsks, lPKs = get_user_keys(username)
        user_to_AEK_SK[username] = HMQV_KServer(ePKc,ePKs,esks,lPKc,lsks,lPKs,username)
        

    def handle_key_confirmation(client_socket,msg,user_to_AEK_SK):
        username = msg['username']
        mac_c = msg['mac_c']
        K_s, K_c = hkdf_expand(user_to_AEK_SK[username],b"K_s"), hkdf_expand(user_to_AEK_SK[username],b"K_c")
        mac_c2 = hmac_sign(K_c,b"Client KC").hex()
        mac_s = hmac_sign(K_s,b"Server KC")
        if mac_c == mac_c2:
            print(f"Key confirmation successful for {username}")
            payload = {"type":"key_confirmation_reaction","mac_s": mac_s.hex()}
            client_socket.sendall(json.dumps(payload).encode('utf-8'))
        else:
            print(f"Key confirmation failed for {username}")


    def handle_login(self, client_socket,msg):
        username = msg['username']           
        if user_exists(username):
            h_pw_alpha = msg['h(pw)_alpha']
            h_pw_alpha = point_from_value(bytes.fromhex(h_pw_alpha))
            salt = get_user_salt(username)
            h_pw_alpha_s = h_pw_alpha * salt
            h_pw_alpha_salt = h_pw_alpha_s.to_bytes()
            enc_client_key_info = get_user_enc_client_key_info(username)
            payload = {"type": "login_reaction", "h(pw)_alpha_salt": h_pw_alpha_salt.hex(), "enc_client_key_info": enc_client_key_info}
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
        'AKE': handle_AKE,
        'key_confirmation': handle_key_confirmation,
    }


    def send_server_message(self,client_socket,message):
        client_socket.sendall(json.dumps({"type":"server_message","message":message}).encode('utf-8'))

        
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
                    server_handler[type](msg, client_socket, self.ePKs, self.esks, self.user_to_AEK_SK)
                elif type == 'key_confirmation':
                    server_handler[type](msg, client_socket, self.user_to_AEK_SK)
                else:
                    server_handler[type](msg, client_socket)

            except Exception as e:
                print(f"Error handling connection: {e}")
                break
    
    def clean_up(self, client_socket):
        client_socket.close()
        self.client_threads.remove(threading.current_thread())
        threading.current_thread().join()

if __name__ == "__main__":
    server = Server()
    server.start()