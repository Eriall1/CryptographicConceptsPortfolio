import math, random

class RSA(object):
    def __init__(self, primeBitLength=6):
        self.primeBitLength = primeBitLength

    def generatePrime(self, bits: int) -> int:
        while True:
            num = random.randrange(2**(bits), 2**(bits+1))
            if self.isPrime(num):
                return num
    
    def isPrime(self, num: int) -> bool:
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for i in range(3, int(math.sqrt(num))+2, 2):
            if num % i == 0:
                return False
        return True
    
    # Copied from wikipedia
    def extended_gcd(self, a: int, b: int) -> tuple[int, int, int]:
        """
        Algorithm extended_gcd(a, b) generated from pseudocode on wikipedia
        https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode

        Returns:
            gcd: The greatest common divisor of a and b
            s: The Bezout coefficient s
            t: The Bezout coefficient t

        Time Complexity:
            O(log(min(a, b)))
        """
        s = 0
        old_s = 1
        r = b
        old_r = a

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        
        if b != 0:
            bezout_t = (old_r - old_s * a) // b
        else:
            bezout_t = 0
        
        return old_r, old_s, bezout_t

    def generateD(self, e: int, phiN: int) -> int:
        gcd, x, y = self.extended_gcd(e, phiN)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phiN

    def generateKeyset(self) -> tuple[int, int]:
        # Generate p and q prime numbers
        p = self.generatePrime(self.primeBitLength)
        q = self.generatePrime(self.primeBitLength)

        # important to security
        while p == q:
            q = self.generatePrime(self.primeBitLength)

        # Calculate n and phiN
        n = p * q
        phiN = (p-1) * (q-1)

        # Generate e (public exponent)
        e = random.randint(1, phiN-1)

        while math.gcd(e, phiN) != 1:
            e = random.randint(1, phiN-1)
        
        d = self.generateD(e, phiN)

        
        print(f"{p=}; {q=}")
        print(f"{n=}; {phiN=}")
        print(f"{e=}; {d=}")

        return (n, e), d
    
    def encrypt(self, plaintext: str, publicKey: tuple[int, int]) -> str:
        n, e = publicKey
        ciphertext = [pow(ord(x), e, n) for x in plaintext]

        return " ".join(map(str, ciphertext))
    
    def decrypt(self, ciphertext: str, n: int, privateKey: int) -> str:
        plaintext = [chr(pow(int(x), privateKey, n)) for x in ciphertext.split(" ")]
        
        return "".join(plaintext)


#region Testing
if __name__ == "__main__":
    rsa = RSA(primeBitLength=6) # 6 bit primes

    publicKey, privateKey = rsa.generateKeyset() # bob's keyset
    publicMod, publicExp = publicKey

    K = "hello world"

    ciphertext = rsa.encrypt(K, publicKey) # alice, with bob's public key

    plaintext = rsa.decrypt(ciphertext, publicKey[0], privateKey) # bob, with his private key


    print("Ciphertext:", ciphertext)
    print("Plaintext:", plaintext)

    assert K == plaintext, "Plaintext and decrypted ciphertext do not match"

#endregion