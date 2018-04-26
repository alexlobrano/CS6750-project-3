# B.py

# Implement the Proof-of-Work (PoW) construction based on hash puzzles discussed in class:
# - SolvePuzzle(x, n): Find a value s in {0, 1}^n such that H(s, x) starts with n zero bits.
# - VerPuzzle(s, x, n): Test if H(s, x) starts with n zero bits.
# Use the SHA-256 hash function. Vary the parameter n from 5 to 25 (at steps of 5) and record the
# timing it takes to solve the puzzle.

from Alex_Lobrano_implementation import *

filename = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = open(filename + '.txt', 'w')

for i in range(5):
	n = (i+1)*5
	x = hashlib.sha256(generate_string(32)).hexdigest()
	print "X:", x
	start = time.time()
	s = solve_puzzle(x, n)
	end = time.time()
	assert verify_puzzle(s, x, n) == 1
	print "Time taken solving puzzle with", n, "zero bits:", end - start, "\n"