#
# ed25519.sage
#
# Generate Ed25519 cofactor verification (*) test vectors
#  with low-order points or base point for signature part R and public key A.
#
# Usage: sage ed25519.sage <n> <l>
#
# Input:
# - number (n) and byte-length (l) of messages
#
# Output:
# - for all (M,A,R) in {n random l-byte messages}x{low-order points, base point}^2 : verify(A,M,(R,S)) == "accept"
#
# (*) See 5.1.7. and 8.8 in RFC 8032.
#
# <patrick.steuer@de.ibm.com>
#

import hashlib
import sys
import os

from cryptography.hazmat.primitives.asymmetric import ed25519

if len(sys.argv) != 3:
	print("Usage: sage ed25519.sage <n> <l>")
	quit()

n = int(sys.argv[1])
l = int(sys.argv[2])

# x0 : first half of SHA-512(private key k).
# x1 : second half of SHA-512(private key k).
# B  : base point
# A  : public key
# R  : first half of signature (R,S)
# c  : cofactor
# h  : SHA-512(R||A||M)
# r  : SHA-512(x1||M)
# M  : message
# L  : groupd order
# p  : field order
#
# Verification eq.
#  c(r + hx0) = cR + chA
#    -------
#       S(x0) = r + hx0
#
# (1) R = A = B =>
#  x0 = (1 + h - r) / h
#
# (2) R = B, A <- low order =>
#  x0 = (1 - r) / h
#
# (3) R <- low order, A = B =>
#  x0 = (h - r) / h
#
# (4) R <- low order, A <- low order =>
#  x0 = -r / h
#

# Field order
p = 2^255 - 19

# Group order
L = 2^252 + 27742317777372353535851937790883648493

# Cofactor
c = 8

# Encoded low-order points
p0 = bytearray.fromhex("0000000000000000000000000000000000000000000000000000000000000000") # order 4
p1 = bytearray.fromhex("0100000000000000000000000000000000000000000000000000000000000000") # order 1
p2 = bytearray.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05") # order 8
p3 = bytearray.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a") # order 8
p4 = bytearray.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") # order 2
p5 = bytearray.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") # order 4
p6 = bytearray.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") # order 1

# Base point
b0 = int(46316835694926478169428394003475163141307993866256225615783033603165251855960).to_bytes(32, byteorder='little'); # order L

# Points
p = [p0, p1, p2, p3, p4, p5, p6, b0]
# Orders
o = [ 4,  1,  8,  8,  2,  4,  1,  L]

accept = 0

def gentestvec(msg, encR, ordR, encA, ordA):
	global accept
	x1 = os.urandom(32)

	# h
	ctx = hashlib.sha512()
	ctx.update(encR)
	ctx.update(encA)
	ctx.update(msg)
	h = ctx.digest()
	h = int.from_bytes(h, byteorder='little')
	h = Mod(h, L)

	# r
	ctx = hashlib.sha512()
	ctx.update(x1)
	ctx.update(msg)
	r = ctx.digest()
	r = int.from_bytes(r, byteorder='little')

	# solve for x0
	if   ordR == L and ordA == L: # (1)
		x0 = Mod((c + c * h - c * r) / (c * h), L)
	elif ordR == L and ordA != L: # (2)
		x0 = Mod((c - c * r) / (c * h), L)
	elif ordR != L and ordA == L: # (3)
		x0 = Mod((c * h - c * r) / (c * h), L)
	elif ordR != L and ordA != L: # (4)
		x0 = Mod((-c * r) / (c * h), L)
		
	# generate S from x0
	S = Mod(r + h * x0, L)
	S = S.lift()
	S = int(S)
	S = S.to_bytes(32, byteorder='little')

	# try to verify
	pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(encA))

	try:
		pub.verify(bytes(encR + S), bytes(M))
	except:
		return

	accept += 1
	print("{")
	print("\"" + msg.hex() + "\", // msg M")
	print("\"" + encA.hex() + "\", // pub A")
	print("\"" + encR.hex() + S.hex() + "\", // sig (R,S)")
	print("},")

for i in range(0, n):
	M = os.urandom(l)

	for i in range(len(p)):
		for j in range(len(p)):
			no = i * len(p) + j
			#print("// no ", no, ", (i = ", i, ", j = ", j, ")")
			gentestvec(M, p[i], o[i], p[j], o[j]);

print("Found", accept, "valid tripples (M,A,(R,S)).")
