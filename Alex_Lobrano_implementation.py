# Alex_Lobrano_implementation.py

import math
import random
import fractions
import hashlib
import string
import time
import datetime
import sys
import Queue

randnum = random.SystemRandom()

# Generate prime number of size n bits
def generate_prime(n):
	
	for i in xrange(3*pow(n,2)):						# Try for 3*n^2 iterations to find a prime number
		p = randnum.getrandbits(n-1)					# Generate n-1 random bits
		p = format(p, 'b')								# Convert to binary string
		for i in range(n - len(p) - 1):
			p = "0" + p									# Add missing zeroes
		p = "1" + p										# Add 1 to front to ensure n bits
		p = int(p, 2)									# Convert back to int
		if(isPrimeMR(p)): 					# Check using Miller-Rabin if p is prime
			return p

# Get number p, test if it's prime using Miller-Rabin
def isPrimeMR(p):
	
	if(p % 2 == 0): 									# Check if p is even
		return False
	u = p - 1											# Set u = p - 1 to begin finding u*2^r
	u = u / 2											# u is now even, so divide it by 2
	r = 1												# r is now equal to 1
	while(u % 2 == 0):									# Continue dividing u by 2 and incrementing r until u is odd
		u = u / 2
		r += 1
	for j in range(10):									# Look for 10 strong witnesses
		a = randnum.randint(2, p-1)						# Choose a random number between 2 and p-1
		if(foundWitness(a,u,r,p)):						# Check if a is a strong witness for p being composite
			return False
	return True
	
# Get number p, test if it is composite by seeing if a is a strong witness with values u and r
def foundWitness(a, u, r, p):
	if((pow(a,u,p) != 1) and (pow(a,u,p) != p-1)):		# Test if a^u mod p is not equal to 1 or -1
		for i in range(1, r):							
			if(pow(a,2**i*u,p) == p-1):					# Test for all {1...r} if a^(u*2^i) is equal to -1
				return False							# If an a^(u*2^i) is equal to -1, then a is not a strong witness
		return True										# If all a^(u*2^i) were checked and none equaled -1, a is a strong witness 
	return False										# If a^u mod p is equal to 1 or -1, then a is not a strong witness

# Returns x such that a*x + b*y = g
def modinv(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return y0
	#return b, y0, x0 #(g,x,y)
	
# Generates a string of size characters
def generate_string(size):
	temp = ''
	for i in range(size):
		temp += random.choice(string.ascii_letters[0:6] + string.digits)
	return temp
	
class Hash_and_Sign_RSA:
	# Initialize RSA, generate e, d
	def __init__(self):
		pass

	# Use generate_prime	
	def gen(self):
		
		# security parameter
		self.n = 1024
		
		# Primes p and q
		self.p = generate_prime(self.n)		# Generate prime p
		self.q = generate_prime(self.n)		# Generate prime q
		
		# RSA modulus N = pq
		self.rsamodulus = self.p * self.q				# Calculate RSA modulus N = p*q
		
		# Phi(N)
		self.phi = (self.p - 1)*(self.q - 1)			# Calculate phi(N) = (p-1)(q-1)
		
		# Public key e
		self.e = randnum.randint(1, self.phi - 1)		# Generate integer e between 1 and phi(N)-1
		while(fractions.gcd(self.e, self.phi) != 1):	# Check if e is relatively prime to phi(N)
			self.e = randnum.randint(1, self.phi - 1)	# If not relatively prime, generate new e and try again
		
		# Secret key d
		self.d = modinv(self.e, self.phi) + self.phi	# Calculate d as modular inverse of e
		
		return self.d, (self.rsamodulus, self.e)		# Return sk and pk
	
	def sign(self, sk, m, N):
		hash = hashlib.sha256(str(m))					# Convert m to string and compute hash
		hash_int = int(hash.hexdigest(), 16)			# Convert hash to integer
		sigma = pow(hash_int, sk, N)					# Calculate sigma = hash_int^sk mod N
		print "Message:", m
		print "Signature:", sigma
		return sigma									# Return signature
	
	def verify(self, pk, m, sigma, N):
		hash = hashlib.sha256(str(m))					# Convert m to string and compute hash
		ver = format(pow(sigma, pk, N), 'x')			# Calculate ver = sigma^pk mod N and save as hex
		print "H(m):", hash.hexdigest()
		print "Signature verification:", ver.zfill(64)
		if(hash.hexdigest() == ver.zfill(64)): 			# Check if H(m) equals ver
			print "Verification success"
			return 1 	
		else: 
			print "Verification fail"
			return 0

class Block:
	def __init__(self, timestamp, sk, pk, transactions, previous_hash, solution, bank, tq):
		self.timestamp = timestamp
		self.transactions = transactions
		mint = [None] * 10
		for i in range(10):
			mint[i] = generate_string(32)
		mint = gen_transaction(pk, sk, pk, mint, bank, tq)
		self.mint = mint
		self.previous_hash = previous_hash
		self.solution = solution
		hash = hashlib.sha256(str(timestamp) + str(transactions) + str(mint) + str(previous_hash) + str(solution))
		self.hash = hash.hexdigest()
		
def solve_puzzle(x, n):
	print "\nSolving puzzle", x, "with", n, "zero bits"
	s = 0
	solved = False
	while(not solved):
		input = format(s, 'b').zfill(n) + format(int(x, 16), 'b').zfill(len(x)*4)	# Compute s || x
		hash = hashlib.sha256(input)												# Compute H(s || x)
		hash_bin = format(int(hash.hexdigest(), 16), 'b')							# Convert hash (hex string) to int, then format as binary string
		# print "Salt:", s
		# print "Input to SHA:", input
		# print "Hash:", hash.hexdigest()
		# print "Hash binary:", hash_bin.zfill(256)
		# print "Leading zero bits:", 256 - len(hash_bin)
		if(256 - len(hash_bin) == n):
			solved = True
			break
		s += 1
	return s
	
def verify_puzzle(s, x, n):
	print "\nVerifying solution", s, "to puzzle", x, "with", n, "zero bits"
	input = format(s, 'b').zfill(n) + format(int(x, 16), 'b').zfill(len(x)*4)		# Compute s || x
	hash = hashlib.sha256(input)													# Compute H(s || x)
	hash_bin = format(int(hash.hexdigest(), 16), 'b')								# Convert hash (hex string) to int, then format as binary string
	print "Hash:", hash.hexdigest()
	print "Hash binary:", hash_bin.zfill(256)
	print "Leading zero bits:", 256 - len(hash_bin)
	if(256 - len(hash_bin) == n):													
		return 1
	else:
		return 0
		
def create_user():
	rsa = Hash_and_Sign_RSA()
	sk, pk = rsa.gen()
	return sk, pk
	
def init_ledger(sk, pk, bank, tq):
	return Block(datetime.datetime.now(), sk, pk, 0, 0, 0, bank, tq)

def init_transaction_queue():
	return Queue.Queue()
	
# pks = (N, e), pkr = (N, e)
def gen_transaction(pks, sks, pkr, serial, bank, tq):
	rsa = Hash_and_Sign_RSA()
	message = (str(pks[1]), str(pkr[1]), serial)
	transaction = rsa.sign(sks, message, pks[0])
	tq.put(transaction)
	if(pks != pkr):									# Check if sender and receiver are different (if not, it's a mint transaction)
		for i in range(len(serial)):
			bank[pks].remove(serial[i])					# Only remove the serial from sender
	for i in range(len(serial)):
		bank[pkr].append(serial[i])
	return transaction

def check_balance(pk, bank):
	return len(bank[pk])
	
def print_coins(pk, bank):
	print "Coins for pk", pk[1]
	for i in range(len(bank[pk])):
		print "Coin", i+1, ":", bank[pk][i]

def gen_block(sk, pk, tq, t, bank, current_block, n):
	transactions = []
	if(t > tq.qsize()):			# Check if there are less than t transactions in the queue
		t = tq.qsize()			# If so, only pop the maximum number of transactions possible
	for i in range(t):
		transactions.append(tq.get())
	solution = solve_puzzle(current_block.hash, n)
	return Block(datetime.datetime.now(), sk, pk, transactions, current_block, solution, bank, tq)