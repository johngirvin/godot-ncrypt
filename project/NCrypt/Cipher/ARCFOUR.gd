# ==============================================================================
# ARCFOUR - RC4 compatible stream cipher
# https://en.wikipedia.org/wiki/RC4
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
class_name ARCFOUR

# ==============================================================================
# PUBLIC  API

"""
Encrypt a buffer using the ARCFOUR scheme and encode as Base64.

Parameters
a_in	:	Input buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Encrypted buffer, same length as input buffer, encoded as a Base64 string.
"""
static func encrypt_base64(a_in:PoolByteArray, a_ky:PoolByteArray, a_drop:int = 0) -> String:
	return Marshalls.raw_to_base64(encrypt_raw(a_in, a_ky, a_drop))


"""
Encrypt a buffer using the ARCFOUR scheme and encode as hexadecimal.

Parameters
a_in	:	Input buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Encrypted buffer, same length as input buffer, encoded as a hexadecimal string.
"""
static func encrypt_hex(a_in:PoolByteArray, a_ky:PoolByteArray, a_drop:int = 0) -> String:
	return NCrypt.raw_to_hex(encrypt_raw(a_in, a_ky, a_drop))


"""
Encrypt a buffer using the ARCFOUR scheme.

Parameters
a_in	:	Input buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Encrypted buffer, same length as input buffer.
"""
static func encrypt_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_drop:int = 0) -> PoolByteArray:
	# initialise
	var il:int = a_in.size()	# input length
	var kl:int = a_ky.size()	# key   length
	assert(il >=   1)	
	assert(kl >=   1)	
	assert(kl <= 256)

	var op:PoolByteArray = PoolByteArray()
	op.resize(il)
	
	var i:int = 0
	var j:int = 0
	var k:int = 0
	var t:int = 0
	
	# key schedule
	var s:PoolByteArray = PoolByteArray()
	s.resize(256)
	for i in range(256):
		s[i] = i
	
	for i in range(256):
		j = (j + s[i] + a_ky[i % kl]) & 0xff
		t    = s[i]
		s[i] = s[j]
		s[j] = t

	# de/encrypt input => output
	# optionally drop some initial keystream bytes
	i = 0
	j = 0
	k = 0
	for p in range(il + a_drop):
		i = (i +    1) & 0xff
		j = (j + s[i]) & 0xff

		t    = s[i]
		s[i] = s[j]
		s[j] = t
		
		if (p >= a_drop):
			op[k] = a_in[k] ^ s[(s[i] + s[j]) & 0xff]
			k += 1	
	
	return op


"""
Decrypt a Base64 encoded buffer using the ARCFOUR scheme.

Parameters
a_in	:	Base64 encoded encrypted buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Decrypted buffer.
"""
static func decrypt_base64(a_in:String, a_ky:PoolByteArray, a_drop:int = 0) -> PoolByteArray:
	return decrypt_raw(Marshalls.base64_to_raw(a_in), a_ky, a_drop)


"""
Decrypt a hexadecimal encoded buffer using the ARCFOUR scheme.

Parameters
a_in	:	Hexadecimal encoded encrypted buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Decrypted buffer.
"""
static func decrypt_hex(a_in:String, a_ky:PoolByteArray, a_drop:int = 0) -> PoolByteArray:
	return encrypt_raw(NCrypt.hex_to_raw(a_in), a_ky, a_drop)


"""
Decrypt a buffer using the ARCFOUR scheme.

Parameters
a_in	:	Encrypted buffer.
a_ky	:	1-256 byte encryption key.
a_drop	:	Number of initial keystream bytes to drop (optional, default 0).

Return	:	Decrypted buffer.
"""
static func decrypt_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_drop:int = 0) -> PoolByteArray:
	return encrypt_raw(a_in, a_ky, a_drop)

