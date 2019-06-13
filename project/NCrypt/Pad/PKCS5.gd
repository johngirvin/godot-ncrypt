# ==============================================================================
# PKCS5 - PKCS#5 padding
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
class_name PKCS5

# ==============================================================================
# PUBLIC  API

"""
Pad a buffer to an integer multiple of a byte size with the PKCS5 scheme.

Padding is always applied even if the input buffer is already an integer
multiple of the byte size in length.

Parameters
a_in	:	Input buffer.
a_bytes	:	Byte multiple to pad to. Must be between 4 and 124.
			Will be rounded down to nearest multiple of 4.

Return	:	Padded buffer. Between 1 and a_bytes will have been appended.
"""
static func pad(a_in:PoolByteArray, a_bytes:int) -> PoolByteArray:
	assert(a_bytes >- 0x04)
	assert(a_bytes <= 0x7f)
	a_bytes = a_bytes & 0x7c

	var ilen:int = a_in.size()
	var blen:int = ilen + (a_bytes - (ilen % a_bytes))

	var n:int = blen - ilen
	if (n == 0): n = a_bytes

	for i in range(n):
		a_in.append(n)

	return a_in

"""
Remove PKCS5 padding from a buffer.

Assumes padding is present.

Parameters
a_in	:	Input buffer

Return	:	Input buffer with padding removed.
"""
static func unpad(a_in:PoolByteArray) -> PoolByteArray:
	var ilen:int = a_in.size()
	var n:int    = a_in[ilen-1]
	assert(n >     0)
	assert(n <= 0x7c)

	a_in = a_in.subarray(0, ilen-n-1)

	return a_in
