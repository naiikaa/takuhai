import socket
import ssl
import threading
import hashlib
import os
import json
from utils.cryptographic_utils import sample_curve_key_pair
from utils.msg_handler import server_handler
from utils.constants import * 

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
