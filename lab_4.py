import hashlib
import bcrypt
import scrypt
import argon2
import sys
from pathlib import Path


rockyou = 'rockyou.txt'
rockyou_1000 = 'rockyou_1000.txt'

    
HASHES = {
    'md5': {
        'hash': '606a85b0d404cfb272c2c7bca1768c9b',
        'salt': bytes.fromhex('604ba56c76edce75')
    },
    'sha256': {
        'hash': 'b713ac97b26e6f18b504a6e61729529773bf00844a3d7e1d274149e50c9943a5',
        'salt': bytes.fromhex('be8ff55288d6ec29')
    },
    'bcrypt': {
        'hash': '$2b$11$R0sm7V1kUxoUanxr9ghlz.YlZxiEyjiV1t9USdxg.yP0NsyvBra7a',
        'salt': None  
    },
    'scrypt': {
        'hash': '9034f524e6c6675c95b84991d8dbf2c926ec783301481272baf8dd870436a5fd317554a952fc39ec94462e57a8e69064671d8bc04b495e54d7c946c841a93f06',
        'salt': bytes.fromhex('18d484f315915fb5')
    },
    'argon2': {
        'hash': '$argon2id$v=19$m=47104,t=4,p=1$KUqF3d3Mc7bekS2HmJd8Zw$+xMgndkhrFHbeJWe/qhTIoKzlIZEqY0xDlQ5gdJqm58',
        'salt': None  
    }
}


def md5_algoritmas(slaptazodziu_sarasas):

    ieskomas_slaptazodis = HASHES['md5']['hash']
    salt = HASHES['md5']['salt']
    
    with open(slaptazodziu_sarasas, 'r', encoding='utf-8', errors='ignore') as failas:
        for slaptazodis in failas:
            slaptazodis = slaptazodis.strip()
            
            md5_hash = hashlib.md5(slaptazodis.encode() + salt.hex().encode()).hexdigest()
            if md5_hash == ieskomas_slaptazodis:
                print(f"MD5 slaptazodis: {slaptazodis}")
                return slaptazodis
    
    print("Nerastas")
    return None

def sha256_algoritmas(slaptazodziu_sarasas):

    ieskomas_slaptazodis = HASHES['sha256']['hash']
    salt = HASHES['sha256']['salt']
    
    with open(slaptazodziu_sarasas, 'r', encoding='utf-8', errors='ignore') as failas:
        for slaptazodis in failas:
            slaptazodis = slaptazodis.strip()
           
            sha256_hash = hashlib.sha256(slaptazodis.encode() + salt.hex().encode()).hexdigest()
            if sha256_hash == ieskomas_slaptazodis:
                print(f"SHA-256 slaptazodis: {slaptazodis}")
                return slaptazodis
    
    print("Nerastas")
    return None

def bcrypt_algoritmas(slaptazodziu_sarasas):

    ieskomas_slaptazodis = HASHES['bcrypt']['hash'].encode()
    
    with open(slaptazodziu_sarasas, 'r', encoding='utf-8', errors='ignore') as failas:
        for slaptazodis in failas:
            slaptazodis = slaptazodis.strip()
            
            if bcrypt.checkpw(slaptazodis.encode(), ieskomas_slaptazodis):
                print(f"bcrypt slaptazodis: {slaptazodis}")
                return slaptazodis
    
    print("Nerastas")
    return None

def scrypt_algoritmas(slaptazodziu_sarasas):

    ieskomas_slaptazodis = HASHES['scrypt']['hash']
    salt = HASHES['scrypt']['salt']
    
    with open(slaptazodziu_sarasas, 'r', encoding='utf-8', errors='ignore') as failas:
        for slaptazodis in failas:
            slaptazodis = slaptazodis.strip()
           
            gautas = scrypt.hash(
                slaptazodis.encode(), salt.hex().encode(),
                N=65536, r=2, p=1, buflen=64
            )
            scrypt_hash = gautas.hex()
            if scrypt_hash == ieskomas_slaptazodis:
                print(f"scrypt slaptazodis: {slaptazodis}")
                return slaptazodis
    
    print("Nerastas")
    return None

def argon2_algoritmas(slaptazodziu_sarasas):

    ieskomas_slaptazodis = HASHES['argon2']['hash']
    # sukuria PasswordHasher objekta
    ph = argon2.PasswordHasher()
    
    with open(slaptazodziu_sarasas, 'r', encoding='utf-8', errors='ignore') as failas:
        for slaptazodis in failas:
            slaptazodis = slaptazodis.strip()
           
            try:
                if ph.verify(ieskomas_slaptazodis, slaptazodis):
                    print(f"Argon2 slaptazodis: {slaptazodis}")
                    return slaptazodis
            except argon2.exceptions.VerifyMismatchError:
                continue
    
    print("Nerastas")
    return None


print("Dictionary Attack: \n")

md5_algoritmas(rockyou)
sha256_algoritmas(rockyou)
bcrypt_algoritmas(rockyou_1000)
scrypt_algoritmas(rockyou_1000)
argon2_algoritmas(rockyou_1000)
    