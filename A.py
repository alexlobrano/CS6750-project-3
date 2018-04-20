# A.py

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
sk, pk = rsa.gen()														# Generate secret key sk (d) and public key pk (N, e)

messages = [0] * 5
sigma = [0] * 5

for i in range(5):
	messages[i] = randnum.randint(1, rsa.rsamodulus - 1)				# Generate message m between 1 and N-1
	while(fractions.gcd(messages[i], rsa.rsamodulus) != 1):				# Check if m is relatively prime to N
		messages[i] = randnum.randint(1, rsa.rsamodulus - 1)			# If not relatively prime, generate new m and try again
	print "Message", i
	sigma[i] = rsa.sign(sk, messages[i], pk[0])							# Compute signature for message m with sk
	
for i in range(5):	
	ver = rsa.verify(pk[1], messages[i], sigma[i], pk[0])				# Verify the signature of each message is valid
	assert ver == 1

for i in range(5):	
	ver = rsa.verify(pk[1], messages[i], sigma[(i+1) % 5], pk[0])		# Verify the signature of different messages are not valid
	assert ver == 0