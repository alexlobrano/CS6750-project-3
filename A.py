# A.py

#
# Implement the Hash-and-Sign RSA digital signature construction. You can reuse your
# implementation of the RSA trapdoor function from last assignment. The signature scheme has three
# algorithms:
# - Gen(): choose e, d such that e*d = 1 mod phi(N) and output pk = e and sk = d;
# - Sign(sk, m): given m in Z_N^*, output signature sigma = H(m)^d mod N.
# - Ver(pk,(m, sigma)): Output 1 if H(m) = sigma^e mod N.
# Use the SHA-256 hash function. Generate several distinct messages and their signatures and verify
# that the Ver algorithm outputs 1 on valid signatures and 0 otherwise.

from Alex_Lobrano_implementation import *

filename = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename + '.txt', 'w')

rsa = Hash_and_Sign_RSA()
sk, pk = rsa.gen(filename)

m = randnum.randint(1, rsa.rsamodulus - 1)				# Generate integer x between 1 and N-1
while(fractions.gcd(m, rsa.rsamodulus) != 1):			# Check if x is relatively prime to N
	m = randnum.randint(1, rsa.rsamodulus - 1)			# If not relatively prime, generate new x and try again
	
sigma = rsa.sign(sk, m, pk[0])
ver = rsa.verify(pk[1], m, sigma, pk[0])
assert ver == 1