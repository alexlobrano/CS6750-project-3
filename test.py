from Alex_Lobrano_implementation import *

filename = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename + '.txt', 'w')

rsa = Hash_and_Sign_RSA()
sk, pk = rsa.gen(filename)

m = randnum.randint(1, rsa.rsamodulus - 1)				# Generate integer x between 1 and N-1
while(fractions.gcd(m, rsa.rsamodulus) != 1):			# Check if x is relatively prime to N
	m = randnum.randint(1, rsa.rsamodulus - 1)			# If not relatively prime, generate new x and try again
	
sigma = rsa.sign(sk, m, pk[0])
test = rsa.verify(pk[1], m, sigma, pk[0])
print test