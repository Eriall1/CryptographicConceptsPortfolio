class EriHash(object):
    """
    Produces a 256 bit hash of a string using the algorithm i have created

    The algorithm works as follows:
    1. If a salt is specified, append it to the plaintext input string
    2. Initialize the hash value to a 128 bit prime number
    3. Iterate over each character in the input string
    4. XOR the current hash value with the ASCII value of the character and bitwise OR it with the XOR of the counter and the previous hash value
    5. Multiply the hash value by the first hashLength digits of the previous hash value
    6. Increment the counter and set the previous hash value to the current hash value
    7. Repeat steps 3-6 for the number of rounds specified

    The hash value is then returned as a 64 character hexadecimal string
    """
    def __init__(self, hashLength=256, salt="", rounds=8):
        # make sure the hash length is a power of 2
        assert (hashLength and (not(hashLength & (hashLength - 1))) )
        self.hashLength = hashLength
        self.salt = salt if salt else ""
        self.rounds = rounds
        self.counter = 0
        self.previousHash = 1
    
    def hash(self, message):
        return self._hash(message)
    
    def xor(self, a, b):
        return (a and not b) or (not a and b)
    
    def _hash(self,plaintext):
        # append the salt
        plaintext += self.salt

        # Initialize the hash value to a 128 bit prime number
        hash_value = 25600128006400320016008004002001
        
        # multiple rounds of hashing
        for _ in range(self.rounds):
            # iterate over each character in the input string
            for char in plaintext:
                # XOR the current hash value with the ASCII value of the character and bitwise OR it with the binary XOR of the counter and the previous hash value
                hash_value ^= ord(char) | self.xor(self.counter, ~self.previousHash)
                # Multiply the hash value by the first hashLength digits of the previous hash value
                hash_value *= int(str(self.previousHash)[:self.hashLength])
                

                # Increment the counter and set the previous hash value to the current hash value
                self.previousHash = hash_value
                self.counter += 1

            hash_value = int(hex(hash_value % (2 ** self.hashLength)), 16)
        
        # reset values for use in next hash; prevents creation of a new object everytime
        self.counter = 0
        self.previousHash = 1

        # Return the hash value, truncated to the first hashLength//4 digits. if the plaintext is empty it will have a lower length then one with input, so pad it with 0s
        return (str(hex(hash_value % (2 ** self.hashLength)))[:self.hashLength//4+2].ljust(self.hashLength//4+2, "0"))[2:]

    def verify(self, message, hash):
        return self._hash(message) == hash

if __name__ == "__main__":
    # test the hash function
    msg = "Leave the pen drive in Room 18.103 at ECU."
    hasher = EriHash()
    hashOfMsg = hasher.hash(msg)
    print("Hash:", hashOfMsg)
    print("Verify:", hasher.verify(msg, hashOfMsg))

#region input testing
""" seen = []
for i in range(len(msg)):
    #print(msg[:i], msg[i+1:])
    
    hashh = EriHash().hash(msg[:i] + ";" +msg[i+1:])
    print(hashh)
    if hashh in seen:
        print("Collision!")
        print(msg[:i], msg[i+1:])
        print(hashh)
        raise Exception("Collision found!")
    seen.append(hashh) """
#endregion

#region sensitivity testing
"""
import string, itertools
seen = []
print("Sensitivity testing started...")
for i in itertools.combinations_with_replacement(string.ascii_letters + string.digits, 5):
    hashed = EriHash().hash("".join(i))
    if hashed in seen:
        print("Collision!")
        print("".join(i))
        print(hashed)
        raise Exception("Collision found!")
    seen.append(hashed)
print("Success!")
"""
#endregion

#region second preimage testing
# second preimage testing
""" print("Second preimage testing started...")
alteredmsg = "Leave the pen drive in Room 18.104 at ECU."
for i in range(1000):
    alteredmsg += " "
    hashh = EriHash().hash(alteredmsg)
    if hashh == hashOfMsg:
        print("Second preimage!")
        print(alteredmsg, alteredmsg == msg)
        print(hashh, hashOfMsg)
        raise Exception("Second preimage found!")
print("Second preimage testing finished!")
print("Success!") """

#endregion