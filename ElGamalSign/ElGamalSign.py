import hashlib
import sys
import getopt
from KeyGen import KeyGen

# y,g,p = public key
# x = private key

# p = prime
# g < p && x < p 

#y = pow(g, x, p)

# k random
# gdc(k, p-1) = 1

# a = pow(g, k, p)
# M = (xa + kb) mod (p-1) - egdc searching b

# signature - a and b

# checker - (y^a * a^b) mod p = g^M mod p

def egcd(x, y):
    xp, xq = 1, 0
    yp, yq = 0, 1
    while y:
        q = x // y
        t, tp, tq = x, xp, xq
        x, xp, xq = y, yp, yq
        y, yp, yq = t - q * x, tp - q * xp, tq - q * xq
    return (xp, xq)

def modInv(a, n):
	r = egcd(a, n)[0] % n
	if r < 0:
		r += n
	return r

def gcd(a, b):
	return a if b == 0 else gcd(b, a % b)

def hash_file(fromFile):
    file = open(fromFile, "rb")
    return hashlib.sha256(file.read()).hexdigest()

def keyGenerate():
    keyGen = KeyGen()
    return keyGen.keyGen(256)

def sign(p, al, bt, k, h):
    keyGen = KeyGen()
    h = int(h, 16)
    s = 0
    while s == 0:
        r = p - 1
        while gcd(r, p - 1) != 1:
            r = keyGen.safe_random(2, p - 1)
        y = pow(al, r, p)
        s = ((h - k * y) * modInv(r, p - 1)) % (p - 1)
        if s < 0:
            s += p - 1
    return (y, s)

def valid(p, al, bt, s, y, h):
    h = int(h, 16)
    L = (pow(bt, y, p) * pow(y, s, p)) % p
    if L < 0:
        L += p
    R = pow(al, h, p)
    return L == R

privKey = keyGenerate()
print(privKey)

signature = sign(privKey[0], privKey[1], privKey[2], privKey[3], hash_file('files/test.txt'))
print(signature)


test = valid(privKey[0], privKey[1], privKey[2], signature[1], signature[0], hash_file('files/test.txt'))

if test:
    print('OK')
else:
    print('ERROR')

#print(hash_file('files/test.txt'))
