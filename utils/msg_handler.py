from ecdsa import VerifyingKey, SigningKey
import json
from cryptographic_utils import *
from database_utils import *

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

def handle_register(client_socket,msg):
    username = msg['username']

    if user_exists(username):
        send_server_message(client_socket,"User already exists. Try logging in.")
    else:
        register_user(msg)
        send_server_message(client_socket,"User registered successfully. Try logging in.")
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
    

server_handler = {
    'login': handle_login,
    'register': handle_register,
    'message': server_handle_message,
    'AKE': handle_AKE,
    'key_confirmation': handle_key_confirmation,
}


def send_server_message(self,client_socket,message):
    client_socket.sendall(json.dumps({"type":"server_message","message":message}).encode('utf-8'))
