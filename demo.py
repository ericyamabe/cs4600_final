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
    def __init__(self):
        self.crypto = Crypto()

    def set_sender_name(self, name: str):
        self.name = name

    def set_sender_private_key(self, private_key: bytes):
        self.sender_private_key = private_key

    def set_message(self, message: str):
        self.message = message.encode()

    def send_message(self, recipient_public_key: bytes):
        message_envelope = self.build_envelope(recipient_public_key)
        print(f"\n{self.name}'s Message Envelope: {json.dumps(message_envelope, indent=2)}")

        # Save the message envelope to a file
        os.makedirs("shared", exist_ok=True)
        message_file = f"shared/{self.name}_message.txt"
        print(f"Writing {self.name}'s Message to {message_file}")
        self.save_envelope(message_envelope, message_file)
        return message_file

    def build_envelope(self, recipient_public_key: bytes) -> dict:
        # 1. Fresh AES-256 key
        aes_key = os.urandom(32)

        # 2. Encrypt message
        iv, ciphertext, gcm_tag = self.crypto.aes_encrypt(aes_key, self.message)

        # 3. Encrypt AES key
        enc_aes_key = self.crypto.rsa_encrypt(recipient_public_key, aes_key)

        # 4. MAC over (enc_aes_key ‖ iv ‖ ciphertext ‖ gcm_tag)
        mac = self.crypto.compute_mac(aes_key, enc_aes_key, iv, ciphertext, gcm_tag)

        def b64(b: bytes) -> str:
            return base64.b64encode(b).decode()

        return {
            "sender":       self.name,
            "enc_aes_key":  b64(enc_aes_key),
            "iv":           b64(iv),
            "ciphertext":   b64(ciphertext),
            "gcm_tag":      b64(gcm_tag),
            "mac":          b64(mac),
        }

    def read_message(self, message_envelop_location: str, receiver_private_key) -> bytes:
        envelope = self.load_message_envelope(message_envelop_location)
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
        decrypted_message = self.crypto.aes_decrypt(aes_key, iv, ciphertext, gcm_tag)
        return decrypted_message.decode()

    def save_envelope(self, envelope: dict, path: str):
        with open(path, "w") as f:
            json.dump(envelope, f, indent=2)


    def load_message_envelope(self, path: str) -> dict:
        with open(path) as f:
            return json.load(f)

def main():
    # **************** Generate keys for Alice and Bob ****************
    alice_private_key, alice_public_key = Crypto.generate_rsa_keypair()
    bob_private_key, bob_public_key = Crypto.generate_rsa_keypair()

    # **************** Setup message objects for Alice and Bob ****************
    AlicesMessage = Message()
    BobsMessage = Message()

    # **************** Setup message object for Alice to use to send messages ****************
    AlicesMessage.set_sender_name("Alice")
    AlicesMessage.set_sender_private_key(alice_private_key)

    # **************** Setup message object for Bob to use to send messages ****************
    BobsMessage.set_sender_name("Bob")
    BobsMessage.set_sender_private_key(bob_private_key)

    # ************************* Alice sends Bob a Message *************************
    print("****** Alice Sends Bob a Message ******")
    # Set Alice's the Message
    alices_original_message = "This is a secret message"
    print(f"Alice's Original Message: {alices_original_message}")
    AlicesMessage.set_message(alices_original_message)

    # We send the message with Bob's public key since he is the recipient
    # this file can now be sent to Bob.
    alice_to_bob_message_file = AlicesMessage.send_message(bob_public_key)

    # Bob retrieves the message envelope from the file and begins recovery with his private key
    print(f"\nBob recieves Alice's file ({alice_to_bob_message_file}) and decrypts and reads Alice's message")
    alices_decrypted_message = BobsMessage.read_message(alice_to_bob_message_file, bob_private_key)
    print("Alice's Decrypted Message:  " + f"\n {alices_decrypted_message}")


    # ************************* Bob sends Alice a Message *************************
    print("\n\n****** Bob Sends Alice a Message ******")
    # Set Bob's Message
    bobs_original_message = "This is ANOTHER secret message"
    print(f"Bob's Original Message: {bobs_original_message}")
    BobsMessage.set_message(bobs_original_message)

    # Bob sends Alice a message with Alice's Public Key
    bob_to_alice_message_file = BobsMessage.send_message(alice_public_key)

    # Alice retrieves Bob's message and decrypts with her private key
    print(f"\nAlice recieves Bob's file ({bob_to_alice_message_file}) and decrypts and reads Bob's message")
    bobs_decrypted_message = AlicesMessage.read_message(bob_to_alice_message_file, alice_private_key)
    print("Bob's Decrypted Message:  " + f"\n  {bobs_decrypted_message}")

main()