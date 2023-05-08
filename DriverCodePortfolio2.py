from RSAPrimeGeneration import RSA
from HashingAlgorithm import EriHash
from StreamCipher import StreamCipher

if __name__ == "__main__":
    #region Setup
    rsaAlice = RSA(6)
    rsaBob = RSA(6)

    hasher = EriHash()
    #endregion

    #region Key Generation
    publicKeyAlice, privateKeyAlice = rsaAlice.generateKeyset()
    publicModAlice, publicExpAlice = publicKeyAlice

    publicKeyBob, privateKeyBob = rsaBob.generateKeyset()
    publicModBob, publicExpBob = publicKeyBob
    #endregion

    m = "Leave the pen drive in Room 18.103 at ECU."

    # alice sets up a shared symmetrical encryption key
    streamCipherKeyAlice = "hello world"

    # alice encrypts the stream cipher key with bob's public key
    streamCipherKeyBob = rsaBob.encrypt(streamCipherKeyAlice, publicKeyBob)

    # she then sends it to bob

    # bob decrypts the stream cipher key with his private key
    streamCipherKeyBobDecrypted = rsaBob.decrypt(streamCipherKeyBob, publicModBob, privateKeyBob)

    # a shared stream cipher is setup, with both parties having secure access to the key
    streamCipher = StreamCipher(streamCipherKeyAlice)

    encryptedm = streamCipher.encrypt(m)

    digestD = hasher.hash(encryptedm)

    # signed with alice's private key
    hashsig = rsaAlice.encrypt(digestD, (publicModAlice, privateKeyAlice))

    # verified with alice's public key
    hashsigdecrypted = rsaAlice.decrypt(hashsig, publicModAlice, publicExpAlice)

    plaintextm = streamCipher.encrypt(encryptedm)

    assert hashsigdecrypted == digestD
    assert plaintextm == m
    assert streamCipherKeyBobDecrypted == streamCipherKeyAlice

    print("Message:", m)
    print("Message Hash:", digestD)
    print("Stream cipher key shared:", streamCipherKeyBobDecrypted==streamCipherKeyAlice)
    print("Encrypted message (stream cipher):", encryptedm)
    print("Signature m:", hashsig)
    print("Decrypted signature m:", hashsigdecrypted)
    print("Signature matches: ", hashsigdecrypted == digestD)
    print("Decrypted message:", plaintextm)
    print("Message matches:", plaintextm == m)