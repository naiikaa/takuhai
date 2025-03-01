import socket
import ssl
import threading
import json
import time
import os
import traceback

from utils.cryptographic_utils import *
from utils.constants import *
from utils.database_utils import *



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
        self.logged_in = False
        self.send_thread = None
        self.listen_thread = None
        self.ik, self.IPK, self.sk, self.SPK, self.ok, self.OPK = create_x3dh_key_info(self.username)
        self.key_bundle_sign = ecdsa_sign(message=self.SPK.to_pem(),private_key=self.ik,nonce=b"")
        self.X3DH_bundles = {}
        self.double_ratchet = None


        while True:
            try:
                self.connect_to_server()
                break
            except Exception as e:
                print(f"Failed to connect to server.")
                print("Retrying in 2 seconds...")
                time.sleep(2)

    def client_handle_message(self,msg):
        iv = bytes.fromhex(msg['iv'])
        cipher = bytes.fromhex(msg['cipher'])
        tag = bytes.fromhex(msg['tag'])
        msg = aes_gcm_decrypt(self.AEK_SK, iv, cipher, b"", tag)
        msg = json.loads(msg)

        decrypted_msg = self.x3dh_decrypt(msg['message'],msg['IPK'],msg['EPK'],msg['OPK'])

        print(f"{msg['username']}: {decrypted_msg}")

    def handle_system_message(self,msg):
        print(f"System: {msg['message']}")
        if msg['message'] == "User registered successfully. Try logging in.":
            self.login()

        if msg['message'] == "User already exists. Try logging in.":
            self.login()
    

    def handle_login_response(self,msg):
        try:
            print("Handling login response")
            h_pw_alpha_salt = point_from_value(bytes.fromhex(msg['h(pw)_alpha_salt']))
            enc_client_key_info = msg['enc_client_key_info']
            h_pw_salt = inverse(self.last_alpha) * h_pw_alpha_salt
            self.rw = hasher(self.password.encode() + h_pw_salt.to_bytes()).digest()
            self.rw_key = hkdf_extract(None, self.rw)
            self.key_info = json.loads(aes_gcm_decrypt(self.rw_key, bytes.fromhex(enc_client_key_info['iv']), bytes.fromhex(enc_client_key_info['cipher']),b"", bytes.fromhex(enc_client_key_info['tag'])))
        except Exception as e:
            self.terminate_with_error("Oops! something went wrong. Check if your password is correct.")

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
            self.logged_in = True
            self.send_thread = threading.Thread(target=self.send_messages)
            self.send_thread.start()
            self.send_x3dh()
        else:
            self.terminate_with_error("Oops! something went wrong. Check if your password is correct.")

    def handle_get_x3dh_keybundle(self,msg):
        target = msg['target']
        keybundle = msg['keybundle']
        if verify_key_bundle(keybundle):
            self.X3DH_bundles[target] = keybundle
            

    client_handler = {
        'encrypted' : client_handle_message,
        'system_message' : handle_system_message,
        'login_response' : handle_login_response,
        'get_x3dh_keybundle' : handle_get_x3dh_keybundle
    }

    def register(self):
        print("Registering user")
        payload = {"type": "register", "username": self.username, "password": self.password}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    
    def login(self):
        print("Logging in")
        self.last_alpha = int.from_bytes(os.urandom(32),'big') % n
        h_pw_alpha = (hash_to_curve(self.password.encode())*self.last_alpha).to_bytes()
        payload = {"type": "login", "username": self.username, "h(pw)_alpha": h_pw_alpha.hex(), "ePKc": self.ePKc.to_string().hex()}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def send_x3dh(self):
        print("Sending X3DH")
        payload = {"type": "x3dh", "username": self.username,  "IPK": self.IPK.to_string().hex(),  "SPK": self.SPK.to_string().hex(),  "OPK": self.OPK.to_string().hex(), "signature": self.key_bundle_sign.hex()}
        iv,cipher,tag = aes_gcm_encrypt(self.AEK_SK, json.dumps(payload))
        payload = {"type": "encrypted","iv": iv.hex(), "cipher": cipher.hex(), "tag": tag.hex()}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def compute_shared_x3dh_key_sender(self,key_bundle):
        ek , EPK = sample_curve_key_pair()
        # DH1 = SPK_B ^ ik
        ik_ecdh = ECDH(CURVE)
        ik_ecdh.load_private_key(self.ik)
        ik_ecdh.load_received_public_key_bytes(bytes.fromhex(key_bundle['SPK']))
        DH1 = ik_ecdh.generate_sharedsecret_bytes()
        # DH2 = IPK_B ^ ek
        ek_ecdh = ECDH(CURVE)
        ek_ecdh.load_private_key(ek)
        ek_ecdh.load_received_public_key_bytes(bytes.fromhex(key_bundle['IPK']))
        DH2 = ek_ecdh.generate_sharedsecret_bytes()
        # DH3 = SPK_B ^ ek
        ek_ecdh.load_received_public_key_bytes(bytes.fromhex(key_bundle['SPK']))
        DH3 = ek_ecdh.generate_sharedsecret_bytes()
        # DH4 = OPK_B ^ ek
        ek_ecdh.load_received_public_key_bytes(bytes.fromhex(key_bundle['OPK']))
        DH4 = ek_ecdh.generate_sharedsecret_bytes()
        # KDF(DH1,DH2,DH3,DH4)
        shared_key = hkdf_extract(salt=None, input_key_material=DH1+DH2+DH3+DH4)
        
        return shared_key, ek, EPK
    
    def  compute_shared_x3dh_key_reciever(self,IPK_A,EPK_A):
        # DH1 = IPK_A ^ sk
        sk_ecdh = ECDH(CURVE)
        sk_ecdh.load_private_key(self.sk)
        sk_ecdh.load_received_public_key_bytes(IPK_A.to_string())
        DH1 = sk_ecdh.generate_sharedsecret_bytes()
        # DH2 = EPK_A ^ ik
        ik_ecdh = ECDH(CURVE)
        ik_ecdh.load_private_key(self.ik)
        ik_ecdh.load_received_public_key_bytes(EPK_A.to_string())
        DH2 = ik_ecdh.generate_sharedsecret_bytes()
        # DH3 = EPK_A ^ sk
        sk_ecdh.load_received_public_key_bytes(EPK_A.to_string())
        DH3 = sk_ecdh.generate_sharedsecret_bytes()
        # DH4 = EPK_A ^ ok
        ok_ecdh = ECDH(CURVE)
        ok_ecdh.load_private_key(self.ok)
        ok_ecdh.load_received_public_key_bytes(EPK_A.to_string())
        DH4 = ok_ecdh.generate_sharedsecret_bytes()
        # KDF(DH1,DH2,DH3,DH4)
        shared_key = hkdf_extract(salt=None, input_key_material=DH1+DH2+DH3+DH4)
        
        return shared_key

    def x3dh_decrypt(self,msg,IPK_A,EPK_A,OPK_A):
        
        IPK_A = VerifyingKey.from_string(bytes.fromhex(IPK_A),curve=CURVE)
        EPK_A = VerifyingKey.from_string(bytes.fromhex(EPK_A),curve=CURVE)
        OPK_A = VerifyingKey.from_string(bytes.fromhex(OPK_A),curve=CURVE)
        iv = bytes.fromhex(msg['iv'])
        cipher = bytes.fromhex(msg['cipher'])
        tag = bytes.fromhex(msg['tag'])
        shared_key = self.compute_shared_x3dh_key_reciever(IPK_A,EPK_A)

        ad = f"{IPK_A.to_string().hex()}{self.IPK.to_string()}".encode()

        plaintext = aes_gcm_decrypt(shared_key, iv, cipher, ad, tag)   
        return plaintext


    def x3dh_encrypt(self,key_bundle,message):
        shared_key, ek, EPK = self.compute_shared_x3dh_key_sender(key_bundle)
        ad = f"{self.IPK.to_string().hex()}{bytes.fromhex(key_bundle['IPK'])}".encode()
        iv,cipher,tag = aes_gcm_encrypt(shared_key, message, ad)
        payload = {"type": "x3dh_encrypted","username":self.username,"IPK":self.IPK.to_string().hex(),"EPK":EPK.to_string().hex(),"OPK":self.OPK.to_string().hex(),"message":{"iv": iv.hex(), "cipher": cipher.hex(), "tag": tag.hex()}}
        return payload

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
                if msg:
                    print(f"Error in handling{msg['type']} message")
                traceback.print_exc()
    
    def get_target_key_bundle(self,target):
        payload = {"type": "get_x3dh_keybundle","username":self.username, "target": target}
        self.ssock.sendall(json.dumps(payload).encode('utf-8'))
                
    def send_messages(self):
        while True:
            try:
                message = input()
                if message == "exit":
                    break
                target = input("Recipient: ")
                if target not in self.X3DH_bundles:
                    #first do X3DH with target and then resend all messages
                    self.get_target_key_bundle(target)
                    while target not in self.X3DH_bundles:
                        pass
                
                message = self.x3dh_encrypt(self.X3DH_bundles[target],message)
                payload = {"type": "message", "username": self.username, "target": target, "message": message}
                iv,cipher,tag = aes_gcm_encrypt(self.AEK_SK, json.dumps(payload))
                payload = {"type": "encrypted","iv": iv.hex(), "cipher": cipher.hex(), "tag": tag.hex()}
                self.ssock.sendall(json.dumps(payload).encode('utf-8'))
            except Exception as e:
                traceback.print_exc()

    def terminate_with_error(self,errormsg):
        print(errormsg)
        self.ssock.close()
        self.sock.close()
        exit(1)

if __name__ == "__main__":
    Client()