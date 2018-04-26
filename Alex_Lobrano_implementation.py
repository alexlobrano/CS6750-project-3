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
		print "Signature:", sigma, "\n"
		return sigma									# Return signature
	
	def verify(self, pk, m, sigma, N):
		hash = hashlib.sha256(str(m))					# Convert m to string and compute hash
		ver = format(pow(sigma, pk, N), 'x')			# Calculate ver = sigma^pk mod N and save as hex
		print "H(m):", hash.hexdigest()
		print "Signature verification:", ver.zfill(64)
		if(hash.hexdigest() == ver.zfill(64)): 			# Check if H(m) equals ver
			print "Verification success\n"
			return 1 	
		else: 
			print "Verification fail\n"
			return 0

# pk = (N, e)
class Block:
	def __init__(self, timestamp, index, sk, pk, transactions, previous_hash, solution, bank, tq):
		self.timestamp = timestamp
		self.index = index
		self.transactions = transactions
		mint = [None] * 10
		for i in range(10):
			mint[i] = generate_string(32)
		mint = gen_transaction(pk, sk, pk, mint, bank, tq, False)	# Mint transaction uses same pk for sender and receiver, and don't add to queue
		self.mint = mint
		self.previous_hash = previous_hash
		self.solution = solution
		hash = hashlib.sha256(str(timestamp) + str(index) + str(transactions) + str(mint) + str(previous_hash) + str(solution))
		self.hash = hash.hexdigest()
		
def solve_puzzle(x, n):
	print "Solving puzzle", x, "with", n, "zero bits"
	s = 0
	solved = False
	while(not solved):
		input = format(s, 'b').zfill(n) + format(int(x, 16), 'b').zfill(len(x)*4)	# Compute s || x
		hash = hashlib.sha256(input)												# Compute H(s || x)
		hash_bin = format(int(hash.hexdigest(), 16), 'b')							# Convert hash (hex string) to int, then format as binary string
		if(256 - len(hash_bin) >= n):												# Check if the number of leading zeroes is at least n
			solved = True
			break
		s += 1																		# If not, increment s and try again
	print "Solution:", s, "\n"
	return s
	
def verify_puzzle(s, x, n):
	print "Verifying solution", s, "to puzzle", x, "with", n, "zero bits"
	input = format(s, 'b').zfill(n) + format(int(x, 16), 'b').zfill(len(x)*4)		# Compute s || x
	hash = hashlib.sha256(input)													# Compute H(s || x)
	hash_bin = format(int(hash.hexdigest(), 16), 'b')								# Convert hash (hex string) to int, then format as binary string
	print "Hash:", hash.hexdigest()
	print "Hash in binary form:", hash_bin.zfill(256)
	print "Leading zero bits:", 256 - len(hash_bin), "\n"
	if(256 - len(hash_bin) >= n):													# Check if the number of leading zeroes is at least n										
		return 1
	else:
		return 0
		
def create_user():
	rsa = Hash_and_Sign_RSA()
	sk, pk = rsa.gen()
	return sk, pk
	
# pk = (N, e)
def init_ledger(sk, pk, bank, tq):
	# Create genesis block 0 with transactions, previous_hash, solution = 0. 
	block = Block(datetime.datetime.now(), 0, sk, pk, 0, 0, 0, bank, tq)
	
	# Process mint transaction
	for i in range(len(block.mint[0][4])):
		pkr = (int(block.mint[0][2]), int(block.mint[0][3]))
		coin = block.mint[0][4][i]
		bank[pkr].append(coin)					# Add coins to receiver (same as sender in this case)
	return block

def init_transaction_queue():
	return Queue.Queue()
	
# pks = (N, e), pkr = (N, e)
def gen_transaction(pks, sks, pkr, serial, bank, tq, add):
	rsa = Hash_and_Sign_RSA()
	message = (str(pks[0]), str(pks[1]), str(pkr[0]), str(pkr[1]), serial)		# Generate message (pks, pkr, coins)
	transaction = (message, rsa.sign(sks, message, pks[0]))						# Save transaction as (message, signature)
	if(add == True):															# Check if you should add the transaction to the queue
		tq.put(transaction)
	return transaction

def check_balance(pk, bank):
	return len(bank[pk])
	
def print_coins(pk, bank):
	print "Coins for pk", pk[1]
	for i in range(len(bank[pk])):
		print "Coin", i+1, ":", bank[pk][i]

# pk = (N, e)
def gen_block(index, sk, pk, tq, t, bank, previous_block, n):
	transactions = []
	transactions_str = ""
	if(t > tq.qsize()):														# Check if there are less than t transactions in the queue
		t = tq.qsize()														# If so, only pop the maximum number of transactions possible
	for i in range(t):														
		temp = tq.get()														# Get a transaction
		transactions_str += str(temp[1])									# Save the signatures as strings
		transactions.append(temp)											# Append the whole transaction to be saved in the block
	solution = solve_puzzle(previous_block.hash + transactions_str, n)		# Solve the puzzle with the previous block hash and transaction strings
	return Block(datetime.datetime.now(), index, sk, pk, transactions, previous_block.hash, solution, bank, tq)
	
def ver_block(index, block, tq, bank, ledger, n):
	print "Verifying block\n"
	rsa = Hash_and_Sign_RSA()
	transactions = block.transactions
	transactions_str = ""
	
	# Verify signatures on transactions
	print "Verifying transactions"
	for i in range(len(transactions)):
		transactions_str += str(transactions[i][1])							# Save the signatures as strings
		if(not rsa.verify(int(transactions[i][0][1]), transactions[i][0], transactions[i][1], int(transactions[i][0][0]))): # pk, m, sigma, N
			print "Verification of transaction signature failed"
			print "Adding transactions back to queue minus the invalid transaction\n"
			for x in range(len(transactions)):								# Put all transactions other than this invalid one back into queue
					if(x == i): continue
					tq.put(transactions[x])
			return 0
	print "All transaction signatures successfully verified\n"
	
	# Verify hash of previous block
	print "Verifying hash of previous block"
	previous_hash = block.previous_hash
	if(previous_hash != ledger[index-1].hash):								# Check if previous hash in block equals hash saved in ledger
		print "Previous hash is incorrect\n"
		return 0
	print "Previous hash is correct\n"
	
	# Verify solution to puzzle
	print "Verifying solution to puzzle"
	solution = block.solution
	if(not verify_puzzle(solution, previous_hash + transactions_str, n)):	# Check if solution in block equals previous hash plus transactions
		print "Solution to puzzle is incorrect\n"
		return 0
	print "Solution to puzzle is correct\n"
	
	# Verify coins are not double spent
	# If sender has sufficient funds for transactions and owns the coins, then it will be processed
	# If a transaction is found involving insufficient funds or double spending, all previous transactions are reversed and added back to queue
	print "Verifying coins are not double spent"
	for i in range(len(transactions)):										# Number of transactions
		for j in range(len(transactions[i][0][4])):							# Number of coins in the transaction
			pks = (int(transactions[i][0][0]), int(transactions[i][0][1]))	# Get public key of sender
			coin = transactions[i][0][4][j]									# Get coin
			if(pks not in bank or coin not in bank[pks]):					# Check if user is in back and coin is owned by user
				if(pks not in bank):
					print "Sender does not exist\n"
				else:
					print "Sender does not own this coin\n"
				for x in range(i):											# Undo transactions processed previous to this one
					for y in range(len(transactions[x][0][4])):				# Return number of coins in transaction
						pks = (int(transactions[x][0][0]), int(transactions[x][0][1]))	# Get public key of sender
						pkr = (int(transactions[x][0][2]), int(transactions[x][0][3]))	# Get public key of receiver
						coin = transactions[x][0][4][y]									# Get coin
						bank[pkr].remove(coin)								# Remove the coins from receiver
						bank[pks].append(coin)								# Add coins to sender
				for x in range(len(transactions)):							# Put all transactions other than this invalid one back into queue
					if(x == i): continue
					tq.put(transactions[x])
				return 0
		for j in range(len(transactions[i][0][4])):							# Number of coins in the transaction
			pks = (int(transactions[i][0][0]), int(transactions[i][0][1]))	# Get public key of sender
			pkr = (int(transactions[i][0][2]), int(transactions[i][0][3]))	# Get public key of receiver
			coin = transactions[i][0][4][j]									# Get coin
			bank[pks].remove(coin)											# Remove the coins from sender
			bank[pkr].append(coin)											# Add coins to receiver
	print "No coins have been double spent\n"
	print "Block has been verified\n"
	
	# Process mint transaction
	print "Processing mint transaction\n"
	for i in range(len(block.mint[0][4])):
		pkr = (int(block.mint[0][2]), int(block.mint[0][3]))
		coin = block.mint[0][4][i]
		bank[pkr].append(coin)					# Add coins to receiver (same as sender in this case)
		
	return 1