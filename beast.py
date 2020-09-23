#!/usr/bin/env python
import sys
import binascii
from textwrap import wrap
import time
import argparse
from Crypto.Cipher import AES
from Crypto import Random

parser = argparse.ArgumentParser(description="Beast exploit simulation")
parser.add_argument('--cookie', type=str, required=False, default="VeRy5eCreTcooki9")
args = parser.parse_args()


def encrypt(msg, iv=None):
    """
    function to encrypt using AES-CBC, hmac here is skipped because it
    is not relevant to the attack
    """
    padding_needed = (AES.block_size - len(msg) % AES.block_size)
    if not iv:
        iv = Random.new().read(AES.block_size)
    msg = msg + chr(padding_needed)*padding_needed
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(msg)

# key agreed during the handshake 
key = Random.new().read(AES.block_size)

# cookie that the attacker would try to guess.
cookie = "Cookie: {}".format(args.cookie)

# to store the decoded part of the cookie
decoded = []

# known_part of the string, we call this prior
prior = "Cookie: "

guess_length = len(cookie) - len(prior)
padding = AES.block_size - len(prior) - 1

# create a padded string to guess the AES.block_size-th byte and rest we know
prior = "#"*padding + prior

for t in range(guess_length):
    i = 0
    while i < 256:
        if padding > 0:
            padded_cookie = "#"*(padding) + cookie
            # send first request
            first_request = encrypt(padded_cookie)
            # send second request where the initialisation vector is from the previous request
            enc = encrypt(padded_cookie, first_request[-AES.block_size:])
        else:
            first_request = encrypt( cookie[-padding:] )
            enc = encrypt(cookie[-padding:], first_request[-AES.block_size:])

        # get the value of the request ciphertext
        original = wrap(binascii.hexlify(enc), 32)

        # apply xor logic for beast using guess for ith char 
        iv = str(enc[-AES.block_size:])
        prev_cipher = str(first_request[-AES.block_size:])
        check = prior + chr(i)
        inject = "".join(chr(ord(a)^ord(b)^ord(c)) for a, b, c in zip(iv, prev_cipher, check))

        # let us simulate the attack by forcing the client to send request of our choice
        # in real world this was done by exploiting the same origin policy of browser
        # by using java applet
        enc = encrypt(inject, iv)
        result = wrap(binascii.hexlify(enc), 32)

        # if the result contains the same cipher block from the original request
        if result[0] == original[0]:
            padding = padding-1
            prior = check[1:]
            decoded.append(chr(i))
            sys.stdout.write("Found character : {}, cookie so far : {}\n".format(chr(i), "".join(decoded)))
            sys.stdout.flush()
            time.sleep(0.1)
            break
        
        i += 1

print
print("Decoded cookie is: {}".format( "".join(decoded)) )