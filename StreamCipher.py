import random, hashlib

# Stream cipher using character-based XOR with a key randomly generated from a seeded PRNG
# the seed for the PRNG is the SHA512 hash of the true encyption / decryption key
class StreamCipher(object):
    def __init__(self, key):
        sha512 = hashlib.sha512()
        sha512.update(key.encode("utf-8"))
        self.key = int(sha512.hexdigest(), 16) # create a seed of length 153-155 depending on input text, All 1s in the hexdigest will result in the lower bond, all Fs result in the upper
    
    def encrypt(self, text): # encrypt and decrypt are the same function since its xor based
        random.seed(self.key)
        return "".join([chr(ord(i) ^ random.randint(0, 2**14)) for i in text])

#best part about the hash is that even without a key you are still able to reliably encrypt and decrypt due to an empty string being hashed regardless
streamCipher = StreamCipher("")

plaintext = "Leave the pen drive in Room 18.103 at ECU."
ciphertext = streamCipher.encrypt(plaintext)
decrypted = streamCipher.encrypt(ciphertext)

assert plaintext == decrypted

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted:", decrypted)
print("Success!")