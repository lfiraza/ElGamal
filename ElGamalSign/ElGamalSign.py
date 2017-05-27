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

def sign(p, g, h, a, hash):
    keyGen = KeyGen()
    hash = int(hash, 16)
    s2 = 0
    while s2 == 0:
        r = p - 1
        while gcd(r, p - 1) != 1:
            r = keyGen.safe_random(2, p - 1)
        s1 = pow(g, r, p)
        s2 = ((hash - a * s1) * modInv(r, p - 1)) % (p - 1)
        if s2 < 0:
            s2 += p - 1
    return (s1, s2)

def valid(p, g, h, s1, s2, hash):
    hash = int(hash, 16)
    if not (s1 > 0 and s1 < p-1): return False
    v = pow(h, s1, p) * pow(s1, s2, p) % p

    if v < 0:
        v += p

    if pow(g, hash, p) == v: 
        return True
    else:
        return False

'''
privKey = keyGenerate()
print(privKey)

signature = sign(privKey[0], privKey[1], privKey[2], privKey[3], hash_file('files/test.txt'))
print(signature)


test = valid(privKey[0], privKey[1], privKey[2], signature[0], signature[1], hash_file('files/test.txt'))

if test:
    print('OK')
else:
    print('ERROR')
'''
def main(argv):

    method = ''
    file = ''
    
    try:
        opts, args = getopt.getopt(argv, "hsvkf:", ["help", "sign", "valid", "keygen" "file="])
    except getopt.GetoptError as error:
        print(error)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
        elif opt in ("-s", "--sign"):
            method = "sign"
        elif opt in ("-v", "--valid"):
            method = "valid"
        elif opt in ("-k", "--keygen"):
            method = "key"
        elif opt in ("-f", "--file"):
            file = arg
        else:
            assert False, "Error"

    if method == 'key':

        keys = keyGenerate()

        fileWrite = open("keys/privkey.txt", "w")
        fileWrite.write(str(keys[3]))
        fileWrite.close()

        fileWrite = open("keys/pubkeys.txt", "w")
        fileWrite.write('\n'.join((str(keys[0]), str(keys[1]), str(keys[2]))))
        fileWrite.close()

    elif method == 'sign':

        public = []
        private = 0    

        fileRead = open("keys/privkey.txt", "r")
        private = int(fileRead.readline().strip())
        fileRead.close()

        fileRead = open("keys/pubkeys.txt", "r")
        public.append(int(fileRead.readline().strip()))
        public.append(int(fileRead.readline().strip()))
        public.append(int(fileRead.readline().strip()))
        fileRead.close()

        signature = sign(public[0], public[1], public[2], private, hash_file("files/"+file))
        
        fileWrite = open("sign/"+file+".sign", "w")
        fileWrite.write('\n'.join((str(signature[0]), str(signature[1]))))
        fileWrite.close()
        
    elif method == 'valid':
        
        public = []
        signature = []

        fileRead = open("keys/pubkeys.txt", "r")
        public.append(int(fileRead.readline().strip()))
        public.append(int(fileRead.readline().strip()))
        public.append(int(fileRead.readline().strip()))
        fileRead.close()

        fileRead = open("sign/"+file+".sign", "r")
        signature.append(int(fileRead.readline().strip()))
        signature.append(int(fileRead.readline().strip()))
        fileRead.close()

        isValid = valid(public[0], public[1], public[2], signature[0], signature[1], hash_file("files/"+file))

        if isValid:
            print("SUCCESS: Signature "+file+".sign is valid for file")
        else:
            print("ERROR: Signature "+file+".sign is NOT valid for file")
    


def help():
    print("Usage: ./ElGamalSign OPTION [VALUE]")
    print("Options:")
    print("     -h --help")
    print("     -s --sing")
    print("     -v --valid")
    print("     -k --keygen")
    print("     -f --file")

if __name__ == "__main__":
    main(sys.argv[1:])    