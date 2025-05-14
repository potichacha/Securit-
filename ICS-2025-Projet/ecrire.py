import zlib, binascii, secrets, os, base64, pickle, datetime, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import Certificate, DNSName, load_pem_x509_certificate

def gencle(bits: int) -> bytes:
    if bits % 8 != 0:
        raise Exception("La taille de la clé doit être un multiple de 8")
    return secrets.token_bytes(bits // 8)

def encRSA(octets: bytes, clepub: rsa.RSAPublicKey) -> bytes:
    return clepub.encrypt(
        octets,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def compresse(texte: str) -> bytes:
    bytestream = texte.encode("utf-8")
    return zlib.compress(bytestream)

def derive(secret: bytes, bits: int) -> bytes:
    if bits % 8 != 0:
        raise ValueError("La taille de la clé doit être un multiple de 8")
    kdf_param = secret[:16]
    salt = secret[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=(bits // 8),
        salt=salt,
        iterations=1_200_000
    )
    return kdf.derive(kdf_param)

def encAES(texte: str, secret: bytes) -> bytes:
    compressed_text = compresse(texte)
    derived_key = derive(secret, 256)
    session_key = derived_key[:16]
    iv = derived_key[16:]
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(compressed_text) + encryptor.finalize()
    return encrypted_data

def chiffre(message: str, pk: rsa.RSAPublicKey) -> bytes:
    secret = gencle(192)
    encrypted_secret = encRSA(secret, pk)
    ciphertext = encAES(message, secret)
    data = (encrypted_secret, ciphertext)
    pickled = pickle.dumps(data)
    return base64.b64encode(pickled)

def sigRSA(message: bytes, sk: rsa.RSAPrivateKey) -> bytes:
    return sk.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def HencS(message: str, pk: rsa.RSAPublicKey, sk: rsa.RSAPrivateKey) -> bytes:
    chiffre64 = chiffre(message, pk)
    signature = sigRSA(chiffre64, sk)
    data = (chiffre64, signature)
    pickled = pickle.dumps(data)
    return base64.b64encode(pickled)

def ReadRSACert(file: str) -> rsa.RSAPublicKey:
    with open(file, "rb") as f:
        data = f.read()
        certificate = x509.load_pem_x509_certificate(data)
        return certificate.public_key()

def readRSA(fic_cle: str):
    with open(fic_cle, 'rb') as file:
        pem = file.read()
        if b"PRIVATE" in pem:
            key = serialization.load_pem_private_key(
                pem,
                password=None
            )
        else:
            key = serialization.load_pem_public_key(pem)
        return key

def main():
    if len(sys.argv) < 4:
        print("Il manque au moins un argument")
        sys.exit(1)

    pkDest = sys.argv[1]
    skExp = sys.argv[2]
    message = sys.argv[3]

    pubKeyDest = ReadRSACert(pkDest)
    privKeyDest = readRSA(skExp)

    res = HencS(message, pubKeyDest, privKeyDest)
    print(res.decode(), end="")

if __name__ == "__main__":
    main()