from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from ecdsa import util,ellipticcurve,curves
from ecdsa.numbertheory import square_root_mod_prime # pip install ecdsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, hashlib
from hashlib import sha256
from ecdsa import SigningKey,VerifyingKey, util # pip install ecdsa
import json
from ecdsa.ellipticcurve import Point
# Use the curve P256, also known as SECP256R1, see https://neuromancer.sk/std/nist/P-256
from ecdsa import NIST256p as CURVE  


HASH_FUNC = hashes.SHA256() # Use SHA256
hasher = sha256
KEY_LEN = 32 # 32 bytes

# Information about P256
P256 = CURVE
a = P256.curve.a()
b = P256.curve.b()
p = P256.curve.p()
n = P256.order

HASH = sha256

def get_order():
    return n

def point_from_value(value):
    return Point.from_bytes(curve=P256.curve, data=value)

def inverse(x: int) -> int:
    return pow(x, -1, n)

def Create_P256_point(x, y):
    P = ellipticcurve.Point(P256.curve, x, y)
    return P

def Is_P256_point(x,y):
    # Since the cofactor is 1, so: is_EC_point = is_group_member
    try:
        ellipticcurve.Point(P256.curve, x, y)
        return True
    except:
        return False

def printable_P256_point(point):
    x = point.x()
    if x != None:
        y = point.y()
        str = f"({x}, {y})"
    else:
        str = "(0, 0)"
    return str

def GetY(x):
    # Given x, compute y such that (x,y) is a point in P256. 
    # If such y does not exist, return None
    p = P256.curve.p()
    rhs = (pow(x, 3, p) + (a * x) + b) % p
    try:
        y = square_root_mod_prime(rhs, p)
        # Two solutions: y0 and p-y0
        return (y, (p - y) % p)
    except:
        # No solution, (x,y) does not exist
        return None


def hash_to_curve(msg_bytes):
    """Warning: This is not a secure implementation (or at least not "uniform") for hash_to_curve. This method is just for illustrating how the DH-OPRF works."""
    """For a secure implementation, please refer to https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html"""
    # Input: msg, an arbitrary-length byte string.
    # Output: P = (x,y), a point in P256.
    h_pw = sha256(msg_bytes)
    h_pw_digest = h_pw.digest()
    first_byte = h_pw_digest[0]
    msb_left = (first_byte & 0x80) != 0
    msb_right = (first_byte & 0x80) != 1

    h_pw_int = int.from_bytes(h_pw_digest,'big') % p

    x = p - h_pw_int
    while True:
        y_int = GetY(x)
        if y_int != None:
            break
        else:
            x = x - 1 % p
    y = y_int[msb_left]
    P_left = Create_P256_point(x,y)

    x = h_pw_int
    while True:
        y_int = GetY(x)
        if y_int != None:
            break
        else:
            x = x + 1 % p
    y = y_int[msb_right]
    P_right = Create_P256_point(x,y)

    P = P_left + P_right

    if x == h_pw_int:
        return P_left
    else:
        return P


# HKDF.Extract
def hkdf_extract(salt, input_key_material, length=KEY_LEN):
    # Extract: Derive the PRK (pseudorandom key)
    hkdf_extract = HKDF(
        algorithm=HASH_FUNC,
        length=length,             # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,             # Salt can be any value or None
        info=None,             # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

# HKDF.Expand
def hkdf_expand(prk, info, length=KEY_LEN):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=HASH_FUNC,
        length=length,         # Desired output length of the final derived key
        salt=None,             # No salt in the Expand phase (PRK is used directly as key)
        info=info,             # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key

# HMAC_Sign
def hmac_sign(key, message): # compute tag = HMAC(key, message)
    # Create an HMAC object using SHA-256
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    tag = h.finalize()
    # Generate the HMAC code (digest)
    return tag

# HMAC_Verify
def hmac_verify(key, message, tag): # Verify tag =? HMAC(key, message)
    # Create a new HMAC object with the same message and key
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    try:
        # Verify by comparing with the provided signature
        h.verify(tag)
        return True
    except Exception:
        return False
    

# Function to sign a message using ECDSA
def ecdsa_sign(message, private_key, nonce = None):
    signature = None
    if nonce: # If the nonce is explicitly specified
        signature = private_key.sign(
            message,
            k=nonce, 
            hashfunc=hasher, 
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=hasher, 
            sigencode=util.sigencode_der
        )
    return signature


# Function to verify ECDSA signature
def ecdsa_verify(signature, message, public_key):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=hasher,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False

# AES-GCM encryption
def aes_gcm_encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)  # GCM mode standard IV size is 96 bits (12 bytes)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Add associated data (not encrypted but authenticated)
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag

# AES-GCM decryption
def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Add associated data (must match what was provided during encryption)
    decryptor.authenticate_additional_data(associated_data)

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

def sample_curve_key_pair():
    sk_ca = SigningKey.generate(CURVE)
    pk_ca = sk_ca.get_verifying_key()
    
    return sk_ca, pk_ca

def HMQV_KServer(ePKc:VerifyingKey, ePKs:VerifyingKey, esks:SigningKey, lPKc:VerifyingKey, lsks:SigningKey, lPKs:VerifyingKey, username:str):
    d = int.from_bytes(hasher(ePKc.to_string()+b"Server").digest(),'big')% n
    e = int.from_bytes(hasher(ePKs.to_string()+username.encode()).digest(),'big')% n
        
    ss = (ePKc.pubkey.point + (lPKc.pubkey.point*d))*((esks.privkey.secret_multiplier+e*lsks.privkey.secret_multiplier)% n)

    AEK_SK = hkdf_expand(ss.to_bytes(),b"")
    return AEK_SK

def HMQV_KClient(username,ePKs,ePKc,eskc,key_info):
    d = int.from_bytes(hasher(ePKc.to_string()+b"Server").digest(),"big") % n
    e = int.from_bytes(hasher(ePKs.to_string()+username.encode()).digest(),"big") % n
    lPKs = VerifyingKey.from_string(bytes.fromhex(key_info['lPKs']),curve=CURVE)
    lskc = SigningKey.from_string(bytes.fromhex(key_info['lskc']),curve=CURVE)
    ss = (ePKs.pubkey.point + (lPKs.pubkey.point*e))*((eskc.privkey.secret_multiplier+d*lskc.privkey.secret_multiplier)% n)
    AEK_SK = hkdf_expand(ss.to_bytes(),b"")
    return AEK_SK

def get_key_conf_key_pair(AKE_SK):
    K_s = hkdf_expand(AKE_SK,b"K_s")
    K_c = hkdf_expand(AKE_SK,b"K_c")
    return K_s, K_c

def create_keyinfo_and_salt(password):
    salt = int.from_bytes(os.urandom(32),'big') % n
    rw = hasher(password.encode() + (hash_to_curve(password.encode())*salt).to_bytes()).digest()  
    print("RW: ", rw)
    rw_key = hkdf_extract(salt=None, input_key_material=rw)
    lskc, lPKc = sample_curve_key_pair()
    lsks, lPKs = sample_curve_key_pair()
    return salt, rw_key, lskc, lPKc, lsks, lPKs