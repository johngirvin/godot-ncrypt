# ==============================================================================
# NCrypt - Cryptographic Primitives in GDScript
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
class_name NCrypt

# ==============================================================================
# CONSTANTS

const B32:int 		= 0xffffffff
const U32_SHIFTS 	= [24,16,8,0]
const U64_SHIFTS 	= [56,48,40,32,24,16,8,0]

# ==============================================================================
# UTILITIES

static func hex_to_raw(a_in:String) -> PoolByteArray:
	var out:PoolByteArray = PoolByteArray()
	
	var hs:String = '0x00'
	for i in range(0, a_in.length(), 2):
		hs[2] = a_in[i]
		hs[3] = a_in[i+1]
		out.append(hs.hex_to_int() & 0xff)
	
	return out
	
static func raw_to_hex(a_in:PoolByteArray) -> String:
	var hex:String = ''
	for i in range(a_in.size()):
		hex += '%02x' % (a_in[i] & 0xff)
	return hex

static func rotr32(n:int, r:int) -> int:
	n = n & B32
	r = r & 0x1f
	return ((n >> r) & B32) | ((n << (32 - r)) & B32)

static func rotl32(n:int, r:int) -> int:
	n = n & B32
	r = r & 0x1f
	return (((n << r) & B32) | ((n >> (32 - r)) & B32)) & B32
