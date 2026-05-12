import os, json, base64, hmac, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    """
    Class to do all things related to cryptography.
    """

    # OAEP Padding configuration to use SHA 256
    _OAEP = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048):
        """
        Generate private/public key pair.  Satisfies Requirement 1 of Final
        :param key_size: Default 2048
        :return: private/public key
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return private_key, private_key.public_key()

    def aes_encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt using AES
        :param key:
        :param plaintext:
        :return: iv, ciphertext, tag
        """
        # Set the IV
        iv = os.urandom(12)
        # Use AES GCM
        aesgcm = AESGCM(key)
        # Encrypt plaintext using IV
        ct = aesgcm.encrypt(iv, plaintext, None)
        # Sets the ciphertext using everything except the last 16 bytes, then sets the tag using the last 16 bytes.
        ciphertext, tag = ct[:-16], ct[-16:]
        return iv, ciphertext, tag

    def aes_decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypts AES encrypted ciphertext
        :param key:
        :param iv:
        :param ciphertext:
        :param tag:
        :return: decrypted data
        """
        # Use AES GCM
        aesgcm = AESGCM(key)
        # Decrypt using the passed IV and ciphertext + tag combination
        return aesgcm.decrypt(iv, ciphertext + tag, None)

    def rsa_encrypt(self, public_key, data: bytes) -> bytes:
        """
        Encrypts with FSA
        :param public_key:
        :param data:
        :return: RSA encrypted ciphertext
        """
        return public_key.encrypt(data, self._OAEP)

    def rsa_decrypt(self, private_key, data: bytes) -> bytes:
        """
        Decrypts RSA ciphertext
        :param private_key:
        :param data:
        :return: plaintext
        """
        return private_key.decrypt(data, self._OAEP)

    def compute_mac(self, mac_key: bytes, *parts: bytes) -> bytes:
        """
        Generates a Keyed-Hashing for Message Authentication (HMAC) using the SHA-256 algorithm
        :param mac_key:
        :param parts:
        :return:
        """
        # This initializes a new HMAC object.
        h = hmac.new(mac_key, digestmod=hashlib.sha256)
        # loops through data parts and feeds them into the hasher one by one.
        for p in parts:
            h.update(p)
        #calculates the final HMAC and returns it as a binary byte string.
        return h.digest()

    def verify_mac(self, mac_key: bytes, expected_mac: bytes, *parts: bytes) -> bool:
        """
        Verifies MAC's authenticity
        :param mac_key:
        :param expected_mac:
        :param parts:
        :return:
        """
        # re-calculates the HMAC using the secret key and the data chunks
        actual = self.compute_mac(mac_key, *parts)
        # returns boolean value if recalculated has matches what was passed.
        return hmac.compare_digest(actual, expected_mac)

class Message:
    """
    Class to do all things related to messages
    """

    def __init__(self):
        """
        Constructor - Initiates the crypto class and saves as a class variable
        """
        self.crypto = Crypto()

    def set_sender_name(self, name: str):
        """
        Sets the sender name for the object
        :param name:
        :return: void
        """
        self.name = name

    def set_sender_private_key(self, private_key: bytes):
        """
        Sets the sender private key to be used
        :param private_key:
        :return: void
        """
        self.sender_private_key = private_key

    def set_message(self, message: str):
        """
        Sets the message to be semt
        :param message:
        :return: void
        """
        self.message = message.encode()

    def send_message(self, recipient_public_key: bytes):
        """
        Sends the message
        :param recipient_public_key:
        :return: message file the envelope has been saved to
        """
        # builds the message envelope
        message_envelope = self.build_envelope(recipient_public_key)
        # output for demo showing the message envelops content
        print(f"\n{self.name}'s Message Envelope: {json.dumps(message_envelope, indent=2)}")

        # Save the message envelope to a file
        os.makedirs("shared", exist_ok=True)
        # Set the file name/location
        message_file = f"shared/{self.name}_message.txt"
        # output for demo showing the message file
        print(f"Writing {self.name}'s Message to {message_file}")
        # save the message envelope
        self.save_envelope(message_envelope, message_file)
        # return the message text file/location
        return message_file

    def build_envelope(self, recipient_public_key: bytes) -> dict:
        """
        Builds the envelope of the message.  Satisfies Requirement 3 and 4 of Final
        :param recipient_public_key:
        :return: Envelope data as a dictionary
        """
        # 1. Fresh AES-256 key
        aes_key = os.urandom(32)

        # 2. Encrypt message
        iv, ciphertext, gcm_tag = self.crypto.aes_encrypt(aes_key, self.message)

        # 3. Encrypt AES key - Satisfies Requirement 3 of Final
        enc_aes_key = self.crypto.rsa_encrypt(recipient_public_key, aes_key)

        # 4. MAC over (enc_aes_key ‖ iv ‖ ciphertext ‖ gcm_tag)
        mac = self.crypto.compute_mac(aes_key, enc_aes_key, iv, ciphertext, gcm_tag)

        def b64(b: bytes) -> str:
            """
            Converts a bytes into a base64 encoded string
            :param b:
            :return: Base 64 encoded string
            """
            return base64.b64encode(b).decode()

        # Satisfies Requirement 4 of Final by appending MAC to data
        return {
            "sender":       self.name,
            "enc_aes_key":  b64(enc_aes_key),
            "iv":           b64(iv),
            "ciphertext":   b64(ciphertext),
            "gcm_tag":      b64(gcm_tag),
            "mac":          b64(mac),
        }

    def read_message(self, message_envelop_location: str, receiver_private_key) -> bytes:
        """
        Reads the message from a file.  Satisfies Requirement 5 of Final
        :param message_envelop_location:
        :param receiver_private_key:
        :return: Decrypted message
        """
        # Loads the message envelope from the file location
        envelope = self.load_message_envelope(message_envelop_location)

        def d64(s: str) -> bytes:
            """
            Decodes a base64 encoded string to a byte array
            :param s:
            :return:
            """
            return base64.b64decode(s)

        # sets AES Key
        enc_aes_key = d64(envelope["enc_aes_key"])
        # sets IV
        iv          = d64(envelope["iv"])
        # sets ciphertext
        ciphertext  = d64(envelope["ciphertext"])
        # sets tag
        gcm_tag     = d64(envelope["gcm_tag"])
        # sets mac
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
        """
        Saves the envelope to a file. Satisfies Requirement 2 of Final
        :param envelope:
        :param path:
        :return:
        """
        with open(path, "w") as f:
            json.dump(envelope, f, indent=2)

    def load_message_envelope(self, path: str) -> dict:
        """
        Loads the envelope from a file
        :param path:
        :return: JSON from a file
        """
        with open(path) as f:
            return json.load(f)

def main():
    # **************** Generate keys for Alice and Bob ****************
    # Satisfies Requirement 1 of Final
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
    # this file can now be sent to Bob. Satisfies Requirement 2, 3, and 4 of Final
    # The file returned is proof of requirement 2.
    alice_to_bob_message_file = AlicesMessage.send_message(bob_public_key)

    # Bob retrieves the message envelope from the file and begins recovery with his private key. Satisfies requirement 5
    # of the Finals
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

    # ************************* Tamper Test *************************
    print("\n\n****** Tamper Test, Alice's message gets tampered with ******")
    # We load the file to tamper with
    message_to_tamper = BobsMessage.load_message_envelope(alice_to_bob_message_file)
    tampered = json.loads(json.dumps(message_to_tamper))
    # Start tampering with flipping a byte
    print(f"Original Ciphertext: {tampered['ciphertext']}")
    ct = bytearray(base64.b64decode(tampered["ciphertext"]))
    # flip byte
    ct[0] ^= 0xFF
    tampered["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    print(f"Tampered Ciphertext: {tampered['ciphertext']}")
    # Save the tampered file
    AlicesMessage.save_envelope(tampered, alice_to_bob_message_file)

    print("\n\nTest with ciphertext tampering")
    try:
        BobsMessage.read_message(alice_to_bob_message_file, bob_private_key)
        print("ERROR: tampered envelope was accepted!")
    except ValueError as e:
        print(f"Tampered envelope - REJECTED: {e}")

    print("\n\nTest with wrong key")
    try:
        BobsMessage.read_message(alices_decrypted_message, alice_private_key)
        print("ERROR: wrong private key was accepted!")
    except Exception as e:
        print("Wrong private key - REJECTED")


if __name__ == "__main__":
    main()