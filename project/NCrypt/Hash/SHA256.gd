# ==============================================================================
# SHA256 - SHA-2 256 bit secure hash
# https://en.wikipedia.org/wiki/SHA-2
# ==============================================================================
# This file is part of NCrypt - Cryptographic Primitives in GDScript
#
# MIT License
#
# Copyright (c) 2019 John Girvin.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ==============================================================================
class_name SHA256

# ==============================================================================
# PUBLIC API

"""
Hash a buffer using the SHA256 scheme and encode as Base64.

Parameters
a_in	:	Input buffer.

Return	:	SHA256 of input buffer, encoded as a Base64 string.
"""
static func hash_base64(a_in:PoolByteArray) -> String:
	return Marshalls.raw_to_base64(hash_raw(a_in))


"""
Hash a buffer using the SHA256 scheme and encode as hexadecimal.

Parameters
a_in	:	Input buffer.

Return	:	SHA256 of input buffer, encoded as a hexadecimal string.
"""
static func hash_hex(a_in:PoolByteArray) -> String:
	return NCrypt.raw_to_hex(hash_raw(a_in))


"""
Hash a buffer using the SHA256 scheme.

Parameters
a_in	:	Input buffer.

Return	:	SHA256 of input buffer.
"""
static func hash_raw(a_in:PoolByteArray) -> PoolByteArray:
	# Initialize hash values
	# (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	var h0:int = 0x6a09e667
	var h1:int = 0xbb67ae85
	var	h2:int = 0x3c6ef372
	var	h3:int = 0xa54ff53a
	var	h4:int = 0x510e527f
	var	h5:int = 0x9b05688c
	var	h6:int = 0x1f83d9ab
	var	h7:int = 0x5be0cd19

	# Pre-process (pad) the input
	# Remember PoolByteArray is passed by value so it is safe to modify the input
	# ...begin with the original message of length L bits
	var l:int = a_in.size() * 8
	# ...append a single '1' bit (and 7 0 bits since this implementation operates at the byte level)
	a_in.append(0x80)
	# ...append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
	while ((a_in.size()+8) & 0x3f != 0): a_in.append(0x00)
	# ...append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
	for i in NCrypt.U64_SHIFTS: a_in.append((l>>i) & 0xff)
	assert(a_in.size()&0x3f == 0)

	# Process the message in successive 512-bit chunks
	var w:Array = [
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	]
	var j:int
	var s0:int
	var s1:int
	var t1:int
	var t2:int
	var ch:int
	var mj:int
	for pos in range(0, a_in.size(), 64):
		# Create a 64-entry message schedule array w[0..63] of 32-bit words
		# Copy chunk into first 16 words w[0..15] of the message schedule array
		for i in range(0,16):
			j = pos + (i*4)
			w[i] = (a_in[j] << 24) | (a_in[j+1] << 16) | (a_in[j+2] << 8) | a_in[j+3]
			pass

		# Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
		for i in range(16,64):
			s0 = NCrypt.rotr32(w[i-15],  7) ^ NCrypt.rotr32(w[i-15], 18) ^ (w[i-15] >>  3)
			s1 = NCrypt.rotr32(w[i- 2], 17) ^ NCrypt.rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10)
			w[i] = (w[i-16] + s0 + w[i-7] + s1) & NCrypt.B32
			pass

		# Initialize working variables to current hash value
		var a:int = h0
		var b:int = h1
		var c:int = h2
		var d:int = h3
		var e:int = h4
		var f:int = h5
		var g:int = h6
		var h:int = h7

		# Compression function main loop
		for i in range(64):
			s1 = NCrypt.rotr32(e,6) ^ NCrypt.rotr32(e,11) ^ NCrypt.rotr32(e,25)
			ch = (e & f) ^ ((~e) & g)
			t1 = (h + s1 + ch + _RK[i] + w[i]) & NCrypt.B32

			s0 = NCrypt.rotr32(a,2) ^ NCrypt.rotr32(a,13) ^ NCrypt.rotr32(a,22)
			mj = (a & b) ^ (a & c) ^ (b & c)
			t2 = (s0 + mj) & NCrypt.B32

			h = g
			g = f
			f = e
			e = (d + t1) & NCrypt.B32
			d = c
			c = b
			b = a
			a = (t1 + t2) & NCrypt.B32
			pass

		# Update the hash value with the compressed chunk
		h0 = (h0 + a) & NCrypt.B32
		h1 = (h1 + b) & NCrypt.B32
		h2 = (h2 + c) & NCrypt.B32
		h3 = (h3 + d) & NCrypt.B32
		h4 = (h4 + e) & NCrypt.B32
		h5 = (h5 + f) & NCrypt.B32
		h6 = (h6 + g) & NCrypt.B32
		h7 = (h7 + h) & NCrypt.B32
		pass

	# Produce the final hash value (big-endian):
	var digest:PoolByteArray = PoolByteArray()
	digest.resize(32)
	j = 0
	for i in NCrypt.U32_SHIFTS:
		digest[j   ] = (h0>>i) & 0xff
		digest[j+ 4] = (h1>>i) & 0xff
		digest[j+ 8] = (h2>>i) & 0xff
		digest[j+12] = (h3>>i) & 0xff
		digest[j+16] = (h4>>i) & 0xff
		digest[j+20] = (h5>>i) & 0xff
		digest[j+24] = (h6>>i) & 0xff
		digest[j+28] = (h7>>i) & 0xff
		j += 1

	return digest
	
# ==============================================================================
# PRIVATE

# round constants
# (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
const _RK:Array = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]