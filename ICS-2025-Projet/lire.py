import zlib, binascii, secrets, os, base64, pickle, datetime, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import Certificate, DNSName

def gencle(bits: int) -> bytes:
    if bits % 8 != 0:
        raise Exception("La taille de la clé doit être un multiple de 8")
    return secrets.token_bytes(bits // 8)

def decRSA(octets: bytes, clepriv: rsa.RSAPrivateKey) -> bytes:
    return clepriv.decrypt(
        octets,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decompresse(comprime: bytes) -> str:
    decompressed_text = zlib.decompress(comprime)
    return decompressed_text.decode("utf-8")

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

def decAES(cryptogramme: bytes, secret: bytes) -> str:
    derived_key = derive(secret, 256)
    session_key = derived_key[:16]
    iv = derived_key[16:]
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(cryptogramme) + decryptor.finalize()
    plaintext = decompresse(decrypted_data)
    return plaintext

def dechiffre(chiffre64: bytes, sk: rsa.RSAPrivateKey) -> str:
    decoded = base64.b64decode(chiffre64)
    encrypted_secret, ciphertext = pickle.loads(decoded)
    secret = decRSA(encrypted_secret, sk)
    return decAES(ciphertext, secret)

def verRSA(message: bytes, signature: bytes, pk: rsa.RSAPublicKey) -> bool:
    try:
        pk.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(e)
        return False

def HdecS(message64: str, pk: rsa.RSAPublicKey, sk: rsa.RSAPrivateKey) -> str:
    padded = message64 + '=' * ((4 - len(message64) % 4) % 4)
    decoded = base64.b64decode(padded)
    ciphertext, signature = pickle.loads(decoded)
    if verRSA(ciphertext, signature, pk):
        return dechiffre(ciphertext, sk)
    raise Exception("Signature verification failed.")

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
    privKeyPath = sys.argv[1]
    pubKeyCert = sys.argv[2]
    messageFile = sys.argv[3]

    privKey = readRSA(privKeyPath)
    pubKey = ReadRSACert(pubKeyCert)

    with open(messageFile, "rb") as f:
        line = f.readline().strip().decode('utf-8')

    res = HdecS(line, pubKey, privKey)
    print(res)

if __name__ == "__main__":
    main()