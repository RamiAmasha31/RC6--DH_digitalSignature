# -*- coding: utf-8 -*-
"""
Created on Mon May 22 01:24:09 2023
This project is the implementation of RC6 algorithm with DH key exchange
key size: 128bits

@author: ראמי
"""


import math
import sys

### main
import time
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes

#rotate right input x, by n bits
def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

#rotate left input x, by n bits
def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits)

#convert input sentence into blocks of binary
#creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for char in sentence:
        binary = bin(ord((char)))[2:]
        if len(binary) < 8:
            binary = "0" * (8 - len(binary)) + binary
        res += binary
        if len(res) >= 32:
            encoded.append(res[:32])
            res = res[32:]
    if res:
        res += "0" * (32 - len(res))  # Pad with zeros if necessary
        encoded.append(res)
    return encoded

#converts 4 blocks array of long int into string
def deBlocker(blocks):
    s = ""
    for ele in blocks:
        temp =bin(ele)[2:]
        if len(temp) <32:
            temp = "0"*(32-len(temp)) + temp
        for i in range(0,4):
            s=s+chr(int(temp[i*8:(i+1)*8],2))
    return s


# generate key s[0... 2r+3] from given input string userkey
def generateKey(userkey):
    r = 12  # Number of rounds
    w = 32  # Word size in bits
    b = len(userkey)  # Length of the user-provided key in bytes
    modulo = 2 ** 32  # Modulo value for modular arithmetic
    s = (2 * r + 4) * [0]  # Array to store the generated round keys
    s[0] = 0xB7E15163  # Initial constant value for the first round key

    # Step 1: Generate Round Keys
    for i in range(1, 2 * r + 4):
        s[i] = (s[i - 1] + 0x9E3779B9) % (2 ** w)  # Generate round keys using modular addition

    # Step 2: Convert User Key
    encoded = blockConverter(userkey)  # Convert user key to binary blocks
    enlength = len(encoded)  # Length of the encoded key
    l = enlength * [0]  # Array to store the encoded key blocks in reverse order

    # Step 3: Reverse and Store Encoded Key
    for i in range(1, enlength + 1):
        l[enlength - i] = int(encoded[i - 1], 2)  # Reverse the encoded key and store it in the array l

    v = 3 * max(enlength, 2 * r + 4)  # Number of mixing iterations
    A = B = i = j = 0  # Temporary variables for mixing operations

    # Step 4: Key Mixing and Round Key Generation
    for index in range(0, v):
        A = s[i] = ROL((s[i] + A + B) % modulo, 3, 32)  # Mix round key with previous round key and temporary variable A
        B = l[j] = ROL((l[j] + A + B) % modulo, (A + B) % 32, 32)  # Mix encoded key block with temporary variables A and B

        i = (i + 1) % (2 * r + 4)  # Cyclically update i
        j = (j + 1) % enlength  # Cyclically update j

    return s  # Return the generated round keys
def encrypt(sentence,s):
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo  ## mixing :combine the current value of A with t
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo 
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*r + 2])%modulo 
    C = (C + s[2*r + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher


def decrypt(esentence, s):
    encoded = blockConverter(esentence)  # Pass esentence directly
    enlength = len(encoded)
    A = int(encoded[0], 2)
    B = int(encoded[1], 2)
    C = int(encoded[2], 2)
    D = int(encoded[3], 2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r = 12
    w = 32
    modulo = 2 ** 32
    lgw = 5
    C = (C - s[2 * r + 3]) % modulo
    A = (A - s[2 * r + 2]) % modulo
    for j in range(1, r + 1):
        i = r + 1 - j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        C = (ROR((C - s[2 * i + 1]) % modulo, tmod, 32) ^ u)
        A = (ROR((A - s[2 * i]) % modulo, umod, 32) ^ t)
    D = (D - s[1]) % modulo
    B = (B - s[0]) % modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher, orgi

def DH():
    # DH parameters
    p = 97001782710325819194621414590353298739571258057935437783558044104158522818261
    g = 3

    print("Now we will exchange the keys between Alice and Bob with the DH algorithm.")
    time.sleep(2)
    a = bytes_to_long(get_random_bytes(16))
    A = pow(g, a, p)
    print("Alice has chosen her private key. A = g^a mod p")
    time.sleep(2)

    print("Alice is sending her public key to Bob!")
    time.sleep(2)

    b = bytes_to_long(get_random_bytes(16))
    B = pow(g, b, p)
    print("Bob has chosen his private key. B = g^b mod p")
    time.sleep(2)

    print("Bob is sending his public key to Alice!")
    time.sleep(2)
    print("Now each one of Alice and Bob is calculating their shared secret key:")
    time.sleep(2)

    print("Alice is calculating B^a mod p")
    time.sleep(2)

    print("Bob is calculating A^b mod p")
    time.sleep(2)

    time.sleep(2)
    secret_alice = pow(B, a, p)
    secret_bob = pow(A, b, p)

    print("Now each one of them has the secret key!")
    time.sleep(2)

    print("Alice's secret key:", secret_alice)
    time.sleep(2)

    print("Bob's secret key:", secret_bob)
    time.sleep(2)
    return secret_alice
def main():
    secret_alice=DH() ### key exchange via DH algorithm without digital signature
    # Convert secret key to string for encryption and decryption
    key = str(secret_alice)

    # Sentence to encrypt
    sentence = "Hello,This project implements the RC6 algorithm, with DH key exchange and blind RSA digital signature"
    l=len(sentence)
    print("Original sentence:", sentence)
    #time.sleep(2)
    k=generateKey(key)
    resEnc=""
    resDec=""
    if(len(sentence)>16):
        for j in range(0,(len(sentence)//16)+1):
            # Encrypt the sentence using the generated key
            i=j*16
            tmp=sentence[i:i+16]
            if len(tmp) < 16:
                tmp = tmp.ljust(16)
            encrypted_sentence, c = encrypt(tmp, k)
            resEnc+=deBlocker(c)

            esen=deBlocker(c)

            d, decrypted_sentence = decrypt(esen, k)
            resDec+=deBlocker(decrypted_sentence)
            tmp=""
    resEnc=resEnc[:l]
    print("Encrypted sentence:",resEnc)
    print("Decrypted sentence:",resDec)
    

# Call the main function
main()