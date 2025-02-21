from utils.constants import *
from utils.cryptographic_utils import *
import json 

#all those single gets are bad and should be replaced with a database that can be queried, but for now it's fine

def get_user_keys(username:str):
    with open(DATABASE_PATH,"r") as db:
        for line in db:
            line = json.loads(line)
            if line['username'] == username:
                lPKc = VerifyingKey.from_string(bytes.fromhex(line['server_key_info']['lPKc']),curve=CURVE)
                lsks = SigningKey.from_string(bytes.fromhex(line['server_key_info']['lsks']),curve=CURVE)
                lPKs = VerifyingKey.from_string(bytes.fromhex(line['server_key_info']['lPKs']),curve=CURVE)
                return lPKc, lsks, lPKs

def get_user_salt(username:str):
    with open(DATABASE_PATH,"r") as db:
        for line in db:
            line = json.loads(line)
            if line['username'] == username:
                return line['salt']

def get_user_enc_client_key_info(username:str):
    with open(DATABASE_PATH,"r") as db:
        for line in db:
            line = json.loads(line)
            if line['username'] == username:
                return line['enc_client_key_info']

#---------------------------------------------------------------------------------------------------------------
    
def user_exists(username:str):
    with open(DATABASE_PATH,"r") as db:
        for line in db:
            line = json.loads(line)
            if line['username'] == username:
                return True
    return False

def register_user(msg):
    username = msg['username']
    password = msg['password']

    salt, rw_key, lskc, lPKc, lsks, lPKs = create_keyinfo_and_salt(password)
    print(rw_key)
    client_key_info = {"lskc":lskc.to_string().hex(), "lPKc":lPKc.to_string().hex(), "lPKs":lPKs.to_string().hex()}    
    server_key_info = {"lPKc":lPKc.to_string().hex(), "lPKs":lPKs.to_string().hex(), "lsks":lsks.to_string().hex()}
    iv,cipher,tag = aes_gcm_encrypt(rw_key, json.dumps(client_key_info), b"")
   
    with open(DATABASE_PATH,"a") as db:
        writable_json = json.dumps({"username":username, "salt":salt, "server_key_info":server_key_info, "enc_client_key_info": {"iv":iv.hex(), "cipher":cipher.hex(), "tag":tag.hex()}})
        db.write(writable_json+"\n")