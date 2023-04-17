import hashlib, random



class BlockCipher(object):
    def __init__(self, key, nonce, blockLength=8, rounds=4):
        assert rounds <= 4, "Rounds must be less than or equal to 4"
        self.key = hashlib.sha512(key.encode()).hexdigest()
        self.nonce = str(int(hashlib.sha256(nonce.encode()).hexdigest(), 16))[:blockLength]
        #print(f"{self.nonce=}")
        random.seed()
        self.blockLength = blockLength
        self.rounds = rounds

    def encrypt(self, plaintext):
        return self._encrypt(plaintext)

    def _encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        blocks = self.getBlocks(plaintext)
        for _ in range(self.rounds):
            currentXor = self.nonce
            #print(currentXor)
            for j in range(len(blocks)):

                
                blocks[j] = self._encryptBlock(blocks[j], currentXor)

                currentXor = hashlib.sha256(blocks[j].encode()).hexdigest()[-self.blockLength:]
        return "".join(blocks)

    def _encryptBlock(self, block, IV):
        block = self._injectIV(block, IV)
        block = self._substitute(block)
        block = self._permute(block)
        block = "".join(chr(ord(i)^ord(v)) for i, v in zip(block, self.key))
        return block

    def _injectIV(self, block, IV):
        return "".join([chr(ord(block[i]) ^ ord(IV[i])) for i in range(self.blockLength)])
    
    def _substitute(self, block):
        random.seed(self.key)
        tmp = ""
        for i in block:
            val = random.randint(0, 2**14)
            #print(val)
            tmp += chr(abs(ord(i) + val))
        return tmp

    def _permute(self, block):
        random.seed(self.key)
        perms = list(range(self.blockLength))
        random.shuffle(perms)
        perms = "".join([str(i) for i in perms])
        
        revperms = "".join([str(perms.index(str(i))) for i in range(0, self.blockLength)])
        #print(perms, revperms)
        permd = "".join([block[int(i)] for i in perms])
        #print(block, permd)
        return permd

    def pad(self, plaintext):
        if len(plaintext) % self.blockLength != 0:
            plaintext += "\x03" * (self.blockLength - (len(plaintext) % self.blockLength) - 1) + str(self.blockLength - (len(plaintext) % self.blockLength))
        return plaintext

    def rempad(self, plaintext):
        return plaintext[:-int(plaintext[-1])] if "\x03" in plaintext else plaintext

    def getBlocks(self, text):
        return [text[i:i+self.blockLength] for i in range(0, len(text), self.blockLength)]

    def decrypt(self, ciphertext):
        return self._decrypt(ciphertext)

    def _decrypt(self, ciphertext):
        blocks = self.getBlocks(ciphertext)

        for _ in range(self.rounds):
            currentXor = self.nonce
            IVS = []
            for i in blocks:
                IVS.append(currentXor)
                currentXor = hashlib.sha256(i.encode()).hexdigest()[-self.blockLength:] 
            for j in range(len(blocks)):
                blocks[j] = self._decryptBlock(blocks[j], IVS[j])
        
        return self.rempad("".join(blocks))

    def _decryptBlock(self, block, IV):
        block = "".join(chr(ord(i)^ord(v)) for i, v in zip(block, self.key))
        block = self._unpermute(block)
        block = self._unsubstitute(block)
        block = self._injectIV(block, IV)
        return block

    def _unpermute(self, block):
        random.seed(self.key)
        perms = list(range(self.blockLength))
        random.shuffle(perms)
        perms = "".join([str(i) for i in perms])

        revperms = "".join([str(perms.index(str(i))) for i in range(0, self.blockLength)])
        return "".join([block[int(i)] for i in revperms])

    def _unsubstitute(self, block):
        random.seed(self.key)
        tmp = ""
        for i in block:
            val = random.randint(0, 2**14)
            #print(ord(i), val)
            tmp += chr(abs(ord(i) - val))
        return tmp




plaintext = "Leave the pen drive in Room 18.103 at ECU."

random.seed()
key = "hello world"
nonce = str(random.randint(0, 2**64))
blockCipher = BlockCipher(key, nonce, 8, 4)

ciphertext = blockCipher.encrypt(plaintext)
deciphertext = blockCipher.decrypt(ciphertext)


print(f"{plaintext=} ")
print(f"{ciphertext=} ")
print(f"{deciphertext=} ")

assert plaintext == deciphertext

print("Success!")