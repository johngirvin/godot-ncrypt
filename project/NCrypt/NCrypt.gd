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

const B32:int 			= 0xffffffff
const U32_SHIFTS 		= [24,16,8,0]
const U64_SHIFTS 		= [56,48,40,32,24,16,8,0]
const U64_SHIFTS_INV	= [0,8,16,24,32,40,48,56]

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

static func int_to_hex(a_in:int) -> String:
	var hex:String = ''
	for i in U64_SHIFTS:
		hex += '%02x' % ((a_in >> i) & 0xff)
	return hex


static func rotr32(n:int, r:int) -> int:
	n = n & B32
	r = r & 0x1f
	if (r == 0): return n
	return ((n >> r) & B32) | ((n << (32 - r)) & B32)

static func rotl32(n:int, r:int) -> int:
	n = n & B32
	r = r & 0x1f
	if (r == 0): return n
	return (((n << r) & B32) | ((n >> (32 - r)) & B32)) & B32


const _rotl64_mask:Array = [
	0xffffffffffffffff,
	0x7fffffffffffffff,
	0x3fffffffffffffff,
	0x1fffffffffffffff,

	0x0fffffffffffffff,
	0x07ffffffffffffff,
	0x03ffffffffffffff,
	0x01ffffffffffffff,

	0x00ffffffffffffff,
	0x007fffffffffffff,
	0x003fffffffffffff,
	0x001fffffffffffff,

	0x000fffffffffffff,
	0x0007ffffffffffff,
	0x0003ffffffffffff,
	0x0001ffffffffffff,

	0x0000ffffffffffff,
	0x00007fffffffffff,
	0x00003fffffffffff,
	0x00001fffffffffff,
	
	0x00000fffffffffff,
	0x000007ffffffffff,
	0x000003ffffffffff,
	0x000001ffffffffff,
	
	0x000000ffffffffff,
	0x0000007fffffffff,
	0x0000003fffffffff,
	0x0000001fffffffff,

	0x0000000fffffffff,
	0x00000007ffffffff,
	0x00000003ffffffff,
	0x00000001ffffffff,

	0x00000000ffffffff,
	0x000000007fffffff,
	0x000000003fffffff,
	0x000000001fffffff,

	0x000000000fffffff,
	0x0000000007ffffff,
	0x0000000003ffffff,
	0x0000000001ffffff,

	0x0000000000ffffff,
	0x00000000007fffff,
	0x00000000003fffff,
	0x00000000001fffff,

	0x00000000000fffff,
	0x000000000007ffff,
	0x000000000003ffff,
	0x000000000001ffff,

	0x000000000000ffff,
	0x0000000000007fff,
	0x0000000000003fff,
	0x0000000000001fff,

	0x0000000000000fff,
	0x00000000000007ff,
	0x00000000000003ff,
	0x00000000000001ff,

	0x00000000000000ff,
	0x000000000000007f,
	0x000000000000003f,
	0x000000000000001f,

	0x000000000000000f,
	0x0000000000000007,
	0x0000000000000003,
	0x0000000000000001,

	0x0000000000000000
]
static func rotl64(n:int, r:int) -> int:
	r = r & 0x3f
	if (r == 0): return n
	# >> preserves the sign bit so we need to mask to perform a logical shift on the second part
	return (n << r) | ((n >> (64-r)) & _rotl64_mask[64-r])
