# ==============================================================================
# HMAC-SHA256 - HMAC secure message authentication code using SHA256
# https://en.wikipedia.org/wiki/HMAC
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
class_name HMACSHA256

# ==============================================================================
# PUBLIC API

"""
Compute the MAC of a buffer using the HMAC-SHA256 scheme and encode as Base64.

Parameters
a_in	:	Input buffer.
a_ky	:	HMAC key.

Return	:	HMAC-SHA256 of input buffer, encoded as a Base64 string.
"""
static func hmac_base64(a_in:PoolByteArray, a_ky:PoolByteArray) -> String:
	return Marshalls.raw_to_base64(hmac_raw(a_in, a_ky))


"""
Compute the MAC of a buffer using the HMAC-SHA256 scheme and encode as hexadecimal.

Parameters
a_in	:	Input buffer.
a_ky	:	HMAC key.

Return	:	HMAC-SHA256 of input buffer, encoded as a hexadecimal string.
"""
static func hmac_hex(a_in:PoolByteArray, a_ky:PoolByteArray) -> String:
	return NCrypt.raw_to_hex(hmac_raw(a_in, a_ky))


"""
Compute the MAC of a buffer using the HMAC-SHA256 scheme.

Parameters
a_in	:	Input buffer.
a_ky	:	HMAC key.

Return	:	HMAC-SHA256 of input buffer.
"""
static func hmac_raw(a_in:PoolByteArray, a_ky:PoolByteArray) -> PoolByteArray:
	# keys longer than hash size are shortened by hashing them
	# keys shorter than hash size are padded to hash size by padding with zeros on the right
	if (a_ky.size() > 64):
		a_ky = SHA256.hash_raw(a_ky)
	while (a_ky.size() < 64):
		a_ky.append(0x00)
	assert(a_ky.size() == 64)

	# generate inner and outer padding keys
	var outer:PoolByteArray = PoolByteArray()
	var inner:PoolByteArray = PoolByteArray()
	for i in range(a_ky.size()):
		outer.append(a_ky[i] ^ 0x5c)
		inner.append(a_ky[i] ^ 0x36)

	# hmac = hash(o_key_pad ∥ hash(i_key_pad ∥ message))
	return SHA256.hash_raw(outer + SHA256.hash_raw(inner + a_in))
