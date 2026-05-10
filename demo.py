import os, json, base64, hmac, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    _OAEP = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return private_key, private_key.public_key()

    def aes_encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, plaintext, None)
        ciphertext, tag = ct[:-16], ct[-16:]
        return iv, ciphertext, tag

    def aes_decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, None)

    def rsa_encrypt(self, public_key, data: bytes) -> bytes:
        return public_key.encrypt(data, self._OAEP)

    def rsa_decrypt(self, private_key, data: bytes) -> bytes:
        return private_key.decrypt(data, self._OAEP)

    def compute_mac(self, mac_key: bytes, *parts: bytes) -> bytes:
        h = hmac.new(mac_key, digestmod=hashlib.sha256)
        for p in parts:
            h.update(p)
        return h.digest()

    def verify_mac(self, mac_key: bytes, expected_mac: bytes, *parts: bytes) -> bool:
        actual = self.compute_mac(mac_key, *parts)
        return hmac.compare_digest(actual, expected_mac)

class Message:
    def __init__(self, message: str):
        self.crypto = Crypto()
        self.message = message.encode()

    def build_envelope(
        self,
        receiver_public_key,
        sender_name: str = "anonymous",
    ) -> dict:
        # 1. Fresh AES-256 key
        aes_key = os.urandom(32)

        # 2. Encrypt message
        iv, ciphertext, gcm_tag = self.crypto.aes_encrypt(aes_key, self.message)

        # 3. Encrypt AES key
        enc_aes_key = self.crypto.rsa_encrypt(receiver_public_key, aes_key)

        # 4. MAC over (enc_aes_key ‖ iv ‖ ciphertext ‖ gcm_tag)
        mac = self.crypto.compute_mac(aes_key, enc_aes_key, iv, ciphertext, gcm_tag)

        def b64(b: bytes) -> str:
            return base64.b64encode(b).decode()

        return {
            "sender": sender_name,
            "enc_aes_key": b64(enc_aes_key),
            "iv":          b64(iv),
            "ciphertext":  b64(ciphertext),
            "gcm_tag":     b64(gcm_tag),
            "mac":         b64(mac),
        }

    def open_envelope(self, envelope: dict, receiver_private_key) -> bytes:
        def d64(s: str) -> bytes:
            return base64.b64decode(s)

        enc_aes_key = d64(envelope["enc_aes_key"])
        iv          = d64(envelope["iv"])
        ciphertext  = d64(envelope["ciphertext"])
        gcm_tag     = d64(envelope["gcm_tag"])
        mac         = d64(envelope["mac"])

        # 3. Decrypt AES key first (needed for MAC verification)
        aes_key = self.crypto.rsa_decrypt(receiver_private_key, enc_aes_key)

        # 2. Verify MAC
        if not self.crypto.verify_mac(aes_key, mac, enc_aes_key, iv, ciphertext, gcm_tag):
            raise ValueError("MAC verification FAILED — message has been tampered with or is corrupt.")

        # 4. Decrypt message (GCM tag verified inside aes_decrypt)
        return self.crypto.aes_decrypt(aes_key, iv, ciphertext, gcm_tag)

    def save_envelope(self, envelope: dict, path: str):
        with open(path, "w") as f:
            json.dump(envelope, f, indent=2)


    def load_envelope(self, path: str) -> dict:
        with open(path) as f:
            return json.load(f)

def main():
    # Generate keys for Alice and Bob
    alice_private_key, alice_public_key = Crypto.generate_rsa_keypair()
    bob_private_key, bob_public_key = Crypto.generate_rsa_keypair()

    # ************************* Alice sends Bob a Message *************************
    print("****** Alice Sends Bob a Message ******")
    # Set the Message
    alices_original_message = "This is a secret message"
    AlicesMessage = Message(alices_original_message)
    print(f"Alice's Original Message: {alices_original_message}")

    # Alice builds the message with Bob's Public Key
    alices_message = AlicesMessage.build_envelope(bob_public_key, sender_name="Alice")
    print(f"\nAlice's Message Envelope: {json.dumps(alices_message, indent=2)}")

    # Save the message envelope to a file
    os.makedirs("shared", exist_ok=True)
    alices_message_file = "shared/alice_message.txt"
    print(f"Writing Alice's Message to {alices_message_file}")
    AlicesMessage.save_envelope(alices_message, alices_message_file)

    # Bob retrieves the message envelope from the file and begins recovery with his private key
    loaded = AlicesMessage.load_envelope("shared/alice_message.txt")
    decrypted = AlicesMessage.open_envelope(loaded, bob_private_key)
    print("\nDecrypted Message:  " + "\n  ".join(decrypted.decode().splitlines()))

    # ************************* Bob sends Alice a Message *************************
    print("\n\n****** Bob Sends Alice a Message ******")
    # Set Bob's Message
    bobs_original_message = "This is ANOTHER secret message"
    BobsMessage = Message(bobs_original_message)
    print(f"Bob's Original Message: {bobs_original_message}")

    # Bob sends Alice a message with Alice's Public Key
    bobs_message = BobsMessage.build_envelope(alice_public_key, sender_name="Bob")
    print(f"\nBob's Message Envelope: {json.dumps(bobs_message, indent=2)}")

    # Save the message envelope to a file
    os.makedirs("shared", exist_ok=True)
    bobs_message_file = "shared/bob_message.txt"
    print(f"Writing Bob's Message to {bobs_message_file}")
    BobsMessage.save_envelope(bobs_message, bobs_message_file)

    # Bob retrieves the message envelope from the file and begins recovery with his private key
    loaded = BobsMessage.load_envelope("shared/alice_message.txt")
    decrypted = BobsMessage.open_envelope(loaded, bob_private_key)
    print("\nDecrypted Message:  " + "\n  ".join(decrypted.decode().splitlines()))

    # ************************* Show tampering *************************
    print("\n\nLet's Tamper With Alice's Message....")
    tampered = json.loads(json.dumps(loaded))          # deep copy
    ct = bytearray(base64.b64decode(tampered["ciphertext"]))
    ct[0] ^= 0xFF                                       # flip byte
    tampered["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    print(f"Tampered Ciphertext: {tampered["ciphertext"]}")
    try:
        AlicesMessage.open_envelope(tampered, bob_private_key)
        print("ERROR: tampered envelope was accepted!")
    except ValueError as e:
        print(f"Tampered envelope correctly REJECTED: {e}")

    try:
        AlicesMessage.open_envelope(loaded, alice_private_key)
        print("ERROR: wrong private key was accepted!")
    except Exception as e:
        print(f"Wrong private key correctly REJECTED")

main()