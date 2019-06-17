# ==============================================================================
# CHACHA - CHACHA stream cipher
# https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
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
class_name CHACHA

# ==============================================================================
# PUBLIC  API

"""
Encrypt a buffer using the CHACHA scheme and encode as Base64.

The counter value is treated as either a 32 or 64 bit big endian integer
depending on if the initialisation vector is 96 or 64 bits respectively.

Reference CHACHA specifies 8/12/20 rounds and a 64 bit initialisation vector.
RFC7539 CHACHA specifies 20 rounds and a 96 bit initialisation vector.

Parameters
a_in	:	Input buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Encrypted buffer, same length as input buffer, encoded as a Base64 string.
"""
static func encrypt_base64(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> String:
	return Marshalls.raw_to_base64(encrypt_raw(a_in, a_ky, a_iv, a_ctr, a_rounds))


"""
Encrypt a buffer using the CHACHA scheme and encode as hexadecimal.

The counter value is treated as either a 32 or 64 bit big endian integer
depending on if the initialisation vector is 96 or 64 bits respectively.

Reference CHACHA specifies 8/12/20 rounds and a 64 bit initialisation vector.
RFC7539 CHACHA specifies 20 rounds and a 96 bit initialisation vector.

Parameters
a_in	:	Input buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Encrypted buffer, same length as input buffer, encoded as a hexadecimal string.
"""
static func encrypt_hex(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> String:
	return NCrypt.raw_to_hex(encrypt_raw(a_in, a_ky, a_iv, a_ctr, a_rounds))


"""
Encrypt a buffer using the CHACHA scheme.

The counter value is treated as either a 32 or 64 bit big endian integer
depending on if the initialisation vector is 96 or 64 bits respectively.

Reference CHACHA specifies 8/12/20 rounds and a 64 bit initialisation vector.
RFC7539 CHACHA specifies 20 rounds and a 96 bit initialisation vector.

Parameters
a_in	:	Input buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Encrypted buffer, same length as input buffer.
"""
static func encrypt_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> PoolByteArray:
	assert(a_ky.size() == 16 || a_ky.size() == 32)
	assert(a_iv.size() ==  8 || a_iv.size() == 12)
	assert(a_iv.size() ==  8 || (a_iv.size() == 12 && a_ctr < 0x100000000))
	assert(a_rounds ==  8 || a_rounds == 12 || a_rounds == 20)
	
	# main loop
	var op:PoolByteArray  = PoolByteArray()
	op.resize(a_in.size())
	var key:PoolByteArray = PoolByteArray()

	var chacha:_ChaChaBlockCipher = _ChaChaBlockCipher.new()
	
	var i  :int = 0
	var ki :int = 64
	var ctr:int = a_ctr
	while (i < a_in.size()):
		# generate new key material for each block
		if (ki == 64):
			key = chacha.chacha20_block(a_ky, a_iv, ctr, a_rounds)
			ki = 0
			ctr += 1

		# xor key with input to get output
		op[i] = a_in[i] ^ key[ki]

		# next byte
		i  += 1
		ki += 1
		
	return op
	

"""
Decrypt a Base64 encoded buffer using the CHACHA scheme.

Parameters
a_in	:	Base64 encoded encrypted buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Decrypted buffer.
"""
static func decrypt_base64(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> PoolByteArray:
	return decrypt_raw(Marshalls.base64_to_raw(a_in), a_ky, a_iv, a_ctr, a_rounds)


"""
Decrypt a hexadecimal encoded buffer using the CHACHA scheme.

Parameters
a_in	:	Hexadecimal encoded encrypted buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Decrypted buffer.
"""
static func decrypt_hex(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> PoolByteArray:
	return encrypt_raw(NCrypt.hex_to_raw(a_in), a_ky, a_iv, a_ctr, a_rounds)


"""
Decrypt a buffer using the CHACHA scheme.

Parameters
a_in	:	Encrypted buffer.
a_ky	:	128/256 bit encryption key.
a_iv	:	64/96 bit initialisation vector.
a_ctr	:	Initial block counter.
a_rounds:	Number of CHACHA rounds 8/12/20

Return	:	Decrypted buffer.
"""
static func decrypt_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int = 1, a_rounds:int = 20) -> PoolByteArray:
	return encrypt_raw(a_in, a_ky, a_iv, a_ctr, a_rounds)

# ==============================================================================
# PRIVATE

class _ChaChaBlockCipher:
	var st:Array 			= []
	var ws:Array 			= []
	var ky:PoolByteArray	= PoolByteArray()
	
	func _init() -> void:
		st.resize(16)
		ws.resize(16)
		for i in range(16):
			st[i] = 0
			ws[i] = 0
		
		ky.resize(64)
		return
	
	func chacha20_block(a_ky:PoolByteArray, a_iv:PoolByteArray, a_ctr:int, a_rounds:int) -> PoolByteArray:
		assert(st.size() == 16)
		assert(ws.size() == 16)
		assert(a_ky.size() == 16 || a_ky.size() == 32)
		assert(a_iv.size() ==  8 || a_iv.size() == 12 || a_iv.size() == 16)

		# initialise state
		var s:int = 4
		if (a_ky.size() == 16):
			# 128 bit key
			# ...'expand 16-byte k'
			st[0] = 0x61707865
			st[1] = 0x3120646e
			st[2] = 0x79622d36
			st[3] = 0x6b206574
			# ...insert 128-bit key twice
			for i in range(0,16,4):
				st[s]   = _u8_to_u32le(a_ky[i], a_ky[i+1], a_ky[i+2], a_ky[i+3])
				st[s+4] = st[s]
				s += 1
		else:
			# 256 bit key
			# ...'expand 32-byte k'
			st[0] = 0x61707865
			st[1] = 0x3320646e
			st[2] = 0x79622d32
			st[3] = 0x6b206574
			# ...insert 256-bit key
			for i in range(0,32,4):
				st[s] = _u8_to_u32le(a_ky[i], a_ky[i+1], a_ky[i+2], a_ky[i+3])
				s += 1
		
		# ...counter & nonce
		if (a_iv.size() == 8):
			# original: 64 bit counter, 64 bit nonce
			st[12] = (a_ctr >> 32) & NCrypt.B32
			st[13] = (a_ctr      ) & NCrypt.B32
			s = 14
			for i in range(0,8,4):
				st[s] = _u8_to_u32le(a_iv[i], a_iv[i+1], a_iv[i+2], a_iv[i+3])
				s += 1
		elif (a_iv.size() == 12):
			# RFC7539: 32 bit counter, 96 bit nonce
			st[12] = a_ctr & NCrypt.B32
			s = 13
			for i in range(0,12,4):
				st[s] = _u8_to_u32le(a_iv[i], a_iv[i+1], a_iv[i+2], a_iv[i+3])
				s += 1
		else:
			# PRNG mode: 128 bit nonce, a_ctr is ignored
			s = 12
			for i in range(0,16,4):
				st[s] = _u8_to_u32le(a_iv[i], a_iv[i+1], a_iv[i+2], a_iv[i+3])
				s += 1
				
		# round loop
		for i in range(ws.size()):
			ws[i] = st[i]

		for r in range(a_rounds>>1):
			_qround(ws, 0, 4, 8,12)
			_qround(ws, 1, 5, 9,13)
			_qround(ws, 2, 6,10,14)
			_qround(ws, 3, 7,11,15)
			_qround(ws, 0, 5,10,15)
			_qround(ws, 1, 6,11,12)
			_qround(ws, 2, 7, 8,13)
			_qround(ws, 3, 4, 9,14)
			
		# create keystream
		var ki:int = 0
		for i in range(st.size()):
			st[i] = (st[i] + ws[i]) & NCrypt.B32
			
			# _u32le_to_u8
			ky[ki  ] = ((st[i]      ) & 0xff)
			ky[ki+1] = ((st[i] >>  8) & 0xff)
			ky[ki+2] = ((st[i] >> 16) & 0xff)
			ky[ki+3] = ((st[i] >> 24) & 0xff)
			ki += 4
		
		return ky
	
	func _qround(st:Array, a:int, b:int, c:int, d:int) -> void:
		st[a] = (st[a] + st[b]) & NCrypt.B32; st[d] ^= st[a]; st[d] = NCrypt.rotl32(st[d], 16)
		st[c] = (st[c] + st[d]) & NCrypt.B32; st[b] ^= st[c]; st[b] = NCrypt.rotl32(st[b], 12)
		st[a] = (st[a] + st[b]) & NCrypt.B32; st[d] ^= st[a]; st[d] = NCrypt.rotl32(st[d],  8)
		st[c] = (st[c] + st[d]) & NCrypt.B32; st[b] ^= st[c]; st[b] = NCrypt.rotl32(st[b],  7)
		return

	func _u8_to_u32le(a:int, b:int, c:int, d:int) -> int:
		return ((a&0xff) | ((b&0xff) << 8) | ((c&0xff) << 16) | ((d&0xff) << 24)) & NCrypt.B32
		