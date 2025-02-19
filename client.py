import socket
import ssl
import threading
import json
import time

from utils.cryptographic_utils import sample_curve_key_pair
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
     
        while True:
            try:
                self.connect_to_server()
                break
            except Exception as e:
                print(f"Failed to connect to server.")
                print("Retrying in 2 seconds...")
                time.sleep(2)

    def client_handle_message(msg):
        print(f"{msg['sender']}: {msg['message']}")

    def handle_system_message(msg):
        print(f"System: {msg['message']}")

    def handle_login_response(msg):
        pass

    def handle_register_response(msg):
        pass


    client_handler = {
        'message' : client_handle_message,
        'system_message' : handle_system_message,
        'login_response' : handle_login_response,
        'register_response' : handle_register_response,

    }

    def connect_to_server(self):
        try:
            self.sock = socket.create_connection(SERVER_ADDRESS)
            self.ssock = self.context.wrap_socket(self.sock, server_hostname='localhost')
            #sending thread
            self.send_thread = threading.Thread(target=self.send_messages)
            self.send_thread.start()
            #listening thread
            self.listen_thread = threading.Thread(target=self.receive_message)
            self.listen_thread.start()    

            self.send_credentials()
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
                type = data['type']
                client_handler[type](msg)

            except Exception as e:
                print(f"Error receiving message: {e}")
                break


if __name__ == "__main__":
    Client()