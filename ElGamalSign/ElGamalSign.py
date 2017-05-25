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

