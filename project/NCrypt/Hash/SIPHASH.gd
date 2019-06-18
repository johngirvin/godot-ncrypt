# ==============================================================================
# SIPHASH - SipHash fast short-input keyed hash / PRF
# https://131002.net/siphash/
# https://en.wikipedia.org/wiki/SipHash
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
class_name SIPHASH

# ==============================================================================
# PUBLIC API

"""
Hash a buffer using the SIPHASH scheme and encode as Base64.

The default is to calculate a 64-bit SipHash-2-4 hash.

Parameters
a_in		:	Input buffer.
a_ky		:	128 bits hash key.
a_crounds	:	SipHash C parameter. Default 2.
a_drounds	:	SipHash D parameter. Default 4.
a_outlen	:	Output hash length in bytes. Must be 8 or 16 (64 or 128 bits).

Return		:	SipHash of input buffer, encoded as a Base64 string.
"""
static func hash_base64(a_in:PoolByteArray, a_ky:PoolByteArray, a_crounds:int = 2, a_drounds:int = 4, a_outlen:int = 8) -> String:
	return Marshalls.raw_to_base64(hash_raw(a_in, a_ky, a_crounds, a_drounds, a_outlen))


"""
Hash a buffer using the SIPHASH scheme and encode as hexadecimal.

The default is to calculate a 64-bit SipHash-2-4 hash.

Parameters
a_in		:	Input buffer.
a_ky		:	128 bits hash key.
a_crounds	:	SipHash C parameter. Default 2.
a_drounds	:	SipHash D parameter. Default 4.
a_outlen	:	Output hash length in bytes. Must be 8 or 16 (64 or 128 bits).

Return		:	SipHash of input buffer, encoded as a hexadecimal string.
"""
static func hash_hex(a_in:PoolByteArray, a_ky:PoolByteArray, a_crounds:int = 2, a_drounds:int = 4, a_outlen:int = 8) -> String:
	return NCrypt.raw_to_hex(hash_raw(a_in, a_ky, a_crounds, a_drounds, a_outlen))


"""
Hash a buffer using the SIPHASH scheme.

The default is to calculate a 64-bit SipHash-2-4 hash.

Parameters
a_in		:	Input buffer.
a_ky		:	128 bits hash key.
a_crounds	:	SipHash C parameter. Default 2.
a_drounds	:	SipHash D parameter. Default 4.
a_outlen	:	Output hash length in bytes. Must be 8 or 16 (64 or 128 bits).

Return		:	SipHash of input buffer.
"""
static func hash_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_crounds:int = 2, a_drounds:int = 4, a_outlen:int = 8) -> PoolByteArray:
	assert(a_ky.size() == 16)
	assert(a_outlen == 8 || a_outlen == 16)
	
	# intialise
	var v0:int = 0x736f6d6570736575;
	var v1:int = 0x646f72616e646f6d;
	var v2:int = 0x6c7967656e657261;
	var v3:int = 0x7465646279746573;
	
	var k0:int = 0
	var k1:int = 0
	for i in range(8):
		k0 = (k0 << 8) | a_ky[7-i]
		k1 = (k1 << 8) | a_ky[7-i+8]
	
	v3 ^= k1
	v2 ^= k0
	v1 ^= k1
	v0 ^= k0
	if (a_outlen == 16): v1 ^= 0xee

	# main processing
	var ilen:int = a_in.size()
	var imax:int = ilen - (ilen % 8)
	var ilft:int = ilen & 7
	var m:int
	for i in range(0, imax, 8):
		m = _u8_to_u64le(a_in[i], a_in[i+1], a_in[i+2], a_in[i+3], a_in[i+4], a_in[i+5], a_in[i+6], a_in[i+7]);
		v3 ^= m;
		
		for j in range(a_crounds):
			v0 += v1
			v1 = NCrypt.rotl64(v1, 13)
			v1 ^= v0
			v0 = NCrypt.rotl64(v0, 32)
			v2 += v3
			v3 = NCrypt.rotl64(v3, 16)
			v3 ^= v2
			v0 += v3
			v3 = NCrypt.rotl64(v3, 21)
			v3 ^= v0
			v2 += v1
			v1 = NCrypt.rotl64(v1, 17)
			v1 ^= v2
			v2 = NCrypt.rotl64(v2, 32)

		v0 ^= m;

	# final block processing
	var b:int = 0
	for i in range(ilft, 0, -1):
		b = (b << 8) | (a_in[imax+i-1] & 0xff)
	b |= (ilen & 0xff) << 56
		
	v3 ^= b

	for j in range(a_crounds):
		v0 += v1
		v1 = NCrypt.rotl64(v1, 13)
		v1 ^= v0
		v0 = NCrypt.rotl64(v0, 32)
		v2 += v3
		v3 = NCrypt.rotl64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = NCrypt.rotl64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = NCrypt.rotl64(v1, 17)
		v1 ^= v2
		v2 = NCrypt.rotl64(v2, 32)

	v0 ^= b

	if (a_outlen == 16)	: v2 ^= 0xee
	else				: v2 ^= 0xff

	# dround loop
	for j in range(a_drounds):
		v0 += v1
		v1 = NCrypt.rotl64(v1, 13)
		v1 ^= v0
		v0 = NCrypt.rotl64(v0, 32)
		v2 += v3
		v3 = NCrypt.rotl64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = NCrypt.rotl64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = NCrypt.rotl64(v1, 17)
		v1 ^= v2
		v2 = NCrypt.rotl64(v2, 32)

	b = v0 ^ v1 ^ v2 ^ v3

	# create return hash
	var op:PoolByteArray = PoolByteArray()
	for i in NCrypt.U64_SHIFTS_INV:
		op.append((b >> i) & 0xff)
	
	if (a_outlen == 16):
		v1 ^= 0xdd
		for j in range(a_drounds):
			v0 += v1
			v1 = NCrypt.rotl64(v1, 13)
			v1 ^= v0
			v0 = NCrypt.rotl64(v0, 32)
			v2 += v3
			v3 = NCrypt.rotl64(v3, 16)
			v3 ^= v2
			v0 += v3
			v3 = NCrypt.rotl64(v3, 21)
			v3 ^= v0
			v2 += v1
			v1 = NCrypt.rotl64(v1, 17)
			v1 ^= v2
			v2 = NCrypt.rotl64(v2, 32)
		b = v0 ^ v1 ^ v2 ^ v3

		for i in NCrypt.U64_SHIFTS_INV:
			op.append((b >> i) & 0xff)
	
	assert(op.size() == a_outlen)
	return op
		
# ==============================================================================
# PRIVATE

static func _u8_to_u64le(a:int, b:int, c:int, d:int, e:int, f:int, g:int, h:int) -> int:
		return ((a&0xff) | ((b&0xff) << 8) | ((c&0xff) << 16) | ((d&0xff) << 24) | ((e&0xff) << 32) | ((f&0xff) << 40) | ((g&0xff) << 48) | ((h&0xff) << 56))
