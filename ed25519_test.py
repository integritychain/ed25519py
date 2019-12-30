# Python 3.7+ Ed25519-SHA-512 tests
# Adapted from https://ed25519.cr.yp.to/software.html retrieved 27 December 2019

import ed25519
import nacl.encoding
import nacl.signing
import random


# Test vectors from ed25519_test.vectors, approx 1/sec on a fast machine
# fields on each input line: sk, pk, m, sm
# each field is hex and colon-terminated
# sk includes pk at end; sm includes m at end

with open("ed25519_test.vectors", 'r') as file_handle:
    for num, line in enumerate(file_handle):
        print("Line number {}".format(num))
        x = line.split(':')
        secret_key = bytes.fromhex(x[0][0:64])
        public_key = ed25519.get_public_key(secret_key)
        message = bytes.fromhex(x[2])
        signature = ed25519.signature(message, secret_key, public_key)
        ed25519.check_valid(signature, message, public_key)
        forged_success = 0
        if len(message) == 0: forged_message = b"x"
        else: forged_message = message[:-1] + bytes([message[-1] ^ 0x01])
        try:
            ed25519.check_valid(signature, forged_message, public_key)
            forged_success = 1
        except ed25519.BadSignatureError:
            pass
        assert not forged_success
        assert x[0] == secret_key.hex() + public_key.hex()
        assert x[1] == public_key.hex()
        assert x[3] == signature.hex() + message.hex()


print("Testing against libsodium")
keyGen = nacl.signing.SigningKey(encoder=nacl.encoding.HexEncoder, seed=b"cafebabe" * 8)

for index in range(50000):
    if index % 100 == 0: print("Index {}".format(index))

    # Generate a new random key pair, check for equivalence
    signing_key = keyGen.generate()
    signing_key2 = bytes(signing_key)
    verify_key = signing_key.verify_key
    verify_key2 = ed25519.get_public_key(bytes(signing_key))
    assert bytes(verify_key) == verify_key2

    # A 'random' message
    message = bytes(random.getrandbits(8) for _ in range(60))

    # Sign the message with the signing key
    signed = signing_key.sign(message)
    signed2 = ed25519.signature(message, signing_key2, verify_key2)
    assert signed.signature == signed2

    # Verify signed (non-tampered) message
    verify_key.verify(signed.message, signed.signature)
    ed25519.check_valid(signed.signature, signed.message, verify_key2)

    # Alter the signed message text
    forged = signed[:-1] + bytes([int(signed[-1]) ^ 1])
    forged2 = signed.message[:-1] + bytes([int(signed.message[-1]) ^ 1])

    # Will raise nacl.exceptions.BadSignatureError, since the signature check fails
    try:
        verify_key.verify(forged)
        raise Exception("forged signature passes verification")
    except nacl.exceptions.BadSignatureError:
        pass  # this is good

    # Confirm new code fails correctly too
    try:
        ed25519.check_valid(signed.signature, forged2, verify_key2)
        raise Exception("forged signature passes verification")
    except ed25519.BadSignatureError:
        pass  # this is good
