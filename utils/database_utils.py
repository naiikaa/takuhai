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

def create_x3dh_key_info(username:str):
    storage_path = LOCAL_USERS_FOLDER+username+".txt"
    if not os.path.exists(storage_path):
        with open(storage_path,"w") as db:
            ik ,IPK  = sample_curve_key_pair()
            sk ,SPK = sample_curve_key_pair()
            ok ,OPK = sample_curve_key_pair()
            db.write(json.dumps({"ik":ik.to_pem().hex(),"IPK":IPK.to_pem().hex(),
                                    "sk":sk.to_pem().hex(),"SPK":SPK.to_pem().hex(),
                                    "ok":ok.to_pem().hex(),"OPK":OPK.to_pem().hex()}) + "\n")
    else:
        with open(storage_path) as db:
            line = json.loads(db.readline())
            ik = SigningKey.from_pem(bytes.fromhex(line['ik']))
            IPK = VerifyingKey.from_pem(bytes.fromhex(line['IPK']))
            sk = SigningKey.from_pem(bytes.fromhex(line['sk']))
            SPK = VerifyingKey.from_pem(bytes.fromhex(line['SPK']))
            ok = SigningKey.from_pem(bytes.fromhex(line['ok']))
            OPK = VerifyingKey.from_pem(bytes.fromhex(line['OPK']))
    return ik, IPK, sk, SPK, ok, OPK

def store_x3dh(msg):
    username = msg['username']
    payload = {"username":username,"IPK":msg['IPK'],"SPK":msg['SPK'],"OPK":msg['OPK'], "signature":msg['signature']}
    with open(X3DH_STORAGE_PATH,"a") as db:
        db.write(json.dumps(payload)+"\n")
    print(f"Stored X3DH keybundle of {username}")

def get_x3dh_keybundle(target:str):
    with open(X3DH_STORAGE_PATH,"r") as db:
        for line in db:
            line = json.loads(line)
            if line['username'] == target:
                return line
    return None