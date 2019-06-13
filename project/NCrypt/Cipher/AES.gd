# ==============================================================================
# AES - Advanced Encryption Standard (AES)
# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
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
class_name AES

# ==============================================================================
# PUBLIC  API

"""
Encrypt a buffer using the AES-ECB scheme and encode as Base64.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.

Return	:	Encrypted buffer, same length as input buffer, encoded as a Base64 string.
"""
static func encrypt_ecb_base64(a_in:PoolByteArray, a_ky:PoolByteArray) -> String:
	return Marshalls.raw_to_base64(encrypt_ecb_raw(a_in, a_ky))


"""
Encrypt a buffer using the AES-ECB scheme and encode as hexadecimal.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.

Return	:	Encrypted buffer, same length as input buffer, encoded as a hexadecimal string.
"""
static func encrypt_ecb_hex(a_in:PoolByteArray, a_ky:PoolByteArray) -> String:
	return NCrypt.raw_to_hex(encrypt_ecb_raw(a_in, a_ky))


"""
Encrypt a buffer using the AES-ECB scheme.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.

Return	:	Encrypted buffer, same length as input buffer.
"""
static func encrypt_ecb_raw(a_in:PoolByteArray, a_ky:PoolByteArray) -> PoolByteArray:
	assert(a_in.size() % 16 == 0)
	assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)

	var op:PoolByteArray = PoolByteArray()

	var aes:_AESBlockCipher = _AESBlockCipher.new(a_ky)
	for pos in range(0, a_in.size(), 16):
		op.append_array( aes.encipher_block(a_in.subarray(pos, pos+15)) )

	return op


"""
Decrypt a Base64 encoded buffer using the AES-ECB scheme.

Parameters
a_in	:	Base64 encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.

Return	:	Decrypted buffer.
"""
static func decrypt_ecb_base64(a_in:String, a_ky:PoolByteArray) -> PoolByteArray:
	return decrypt_ecb_raw(Marshalls.base64_to_raw(a_in), a_ky)


"""
Decrypt a hexadecimal encoded buffer using the AES-ECB scheme.

Parameters
a_in	:	Hexadecimal encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.

Return	:	Decrypted buffer.
"""
static func decrypt_ecb_hex(a_in:String, a_ky:PoolByteArray) -> PoolByteArray:
	return decrypt_ecb_raw(NCrypt.hex_to_raw(a_in), a_ky)


"""
Decrypt a buffer using the AES-ECB scheme.

Parameters
a_in	:	Encrypted buffer.
a_ky	:	128/192/256 bits encryption key.

Return	:	Decrypted buffer.
"""
static func decrypt_ecb_raw(a_in:PoolByteArray, a_ky:PoolByteArray) -> PoolByteArray:
	assert(a_in.size() % 16 == 0)
	assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)

	var op:PoolByteArray = PoolByteArray()

	var aes:_AESBlockCipher = _AESBlockCipher.new(a_ky)
	for pos in range(0, a_in.size(), 16):
		op.append_array( aes.decipher_block(a_in.subarray(pos, pos+15)) )

	return op


"""
Encrypt a buffer using the AES-CBC scheme and encode as Base64.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector.

Return	:	Encrypted buffer encoded as a Base64 string.
"""
static func encrypt_cbc_base64(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> String:
	return Marshalls.raw_to_base64(encrypt_cbc_raw(a_in, a_ky, a_iv))


"""
Encrypt a buffer using the AES-CBC scheme and encode as hexadecimal.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector.

Return	:	Encrypted buffer encoded as a hexadecimal string.
"""
static func encrypt_cbc_hex(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> String:
	return NCrypt.raw_to_hex(encrypt_cbc_raw(a_in, a_ky, a_iv))


"""
Encrypt a buffer using the AES-CBC scheme.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector.

Return	:	Encrypted buffer.
"""
static func encrypt_cbc_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	assert(a_in.size() % 16 == 0)
	assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)
	assert(a_iv.size() == 16)

	var op:PoolByteArray = PoolByteArray()
	var iv:PoolByteArray = a_iv

	var aes:_AESBlockCipher = _AESBlockCipher.new(a_ky)
	for pos in range(0, a_in.size(), 16):
		# get next block
		var blk:PoolByteArray = a_in.subarray(pos, pos+15)

		# xor with iv
		for i in range(16):	blk[i] ^= iv[i]

		# encrypt block, and copy as iv for next block
		iv = aes.encipher_block(blk)

		# add block to output
		op.append_array(iv)

	return op


"""
Decrypt a Base64 encoded buffer using the AES-CBC scheme.

Parameters
a_in	:	Base64 encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	Initialisation vector.

Return	:	Decrypted buffer.
"""
static func decrypt_cbc_base64(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	return decrypt_cbc_raw(Marshalls.base64_to_raw(a_in), a_ky, a_iv)


"""
Decrypt a hexadecimal encoded buffer using the AES-CBC scheme.

Parameters
a_in	:	Hexadecimal encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector.

Return	:	Decrypted buffer.
"""
static func decrypt_cbc_hex(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	return decrypt_cbc_raw(NCrypt.hex_to_raw(a_in), a_ky, a_iv)


"""
Decrypt a buffer using the AES-CBC scheme.

Parameters
a_in	:	Encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector.

Return	:	Decrypted buffer.
"""
static func decrypt_cbc_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	assert(a_in.size() % 16 == 0)
	assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)
	assert(a_iv.size() == 16)

	var op:PoolByteArray = PoolByteArray()
	var iv:PoolByteArray = a_iv

	var aes:_AESBlockCipher = _AESBlockCipher.new(a_ky)
	for pos in range(0, a_in.size(), 16):
		# decrypt next block
		var blk:PoolByteArray = aes.decipher_block(a_in.subarray(pos, pos+15))
		# xor with previous iv
		for i in range(16):	blk[i] ^= iv[i]
		# append to output
		op.append_array(blk)
		# set pre-decryption content block as the iv for the next block
		for i in range(16):	iv[i] = a_in[pos+i]

	return op


"""
Encrypt a buffer using the AES-CTR scheme and encode as Base64.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Encrypted buffer encoded as a Base64 string.
"""
static func encrypt_ctr_base64(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> String:
	return Marshalls.raw_to_base64(encrypt_ctr_raw(a_in, a_ky, a_iv))


"""
Encrypt a buffer using the AES-CTR scheme and encode as hexadecimal.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Encrypted buffer encoded as a hexadecimal string.
"""
static func encrypt_ctr_hex(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> String:
	return NCrypt.raw_to_hex(encrypt_ctr_raw(a_in, a_ky, a_iv))


"""
Encrypt a buffer using the AES-CTR scheme.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Input buffer. Must be a multiple of 128 bits in length.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Encrypted buffer.
"""
static func encrypt_ctr_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)
	assert(a_iv.size() == 16)

	var op:PoolByteArray  = PoolByteArray()
	op.resize(a_in.size())
	var ctr:PoolByteArray = a_iv
	var key:PoolByteArray = PoolByteArray()

	var aes:_AESBlockCipher = _AESBlockCipher.new(a_ky)

	var i :int = 0
	var ki:int = 16
	while (i < a_in.size()):
		if (ki == 16):
			# generate more key material
			key = aes.encipher_block(ctr)
			ki = 0

			# increment counter (big endian)
			for i in range(15,-1,-1):
				ctr[i] = (ctr[i] + 1) & 0xff
				if (ctr[i] != 0): break
				pass

		# xor key with input to get output
		op[i] = a_in[i] ^ key[ki]

		# next byte
		i  += 1
		ki += 1

	return op


"""
Decrypt a Base64 encoded buffer using the AES-CTR scheme.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Base64 encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Decrypted buffer.
"""
static func decrypt_ctr_base64(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	return encrypt_ctr_raw(Marshalls.base64_to_raw(a_in), a_ky, a_iv)


"""
Decrypt a hexadecimal encoded buffer using the AES-CTR scheme.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Hexadecimal encoded encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Decrypted buffer.
"""
static func decrypt_ctr_hex(a_in:String, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	return encrypt_ctr_raw(NCrypt.hex_to_raw(a_in), a_ky, a_iv)


"""
Decrypt a buffer using the AES-CTR scheme.

The counter is incremented as a 128 bit big endian integer for each
processed block.

Parameters
a_in	:	Encrypted buffer.
a_ky	:	128/192/256 bits encryption key.
a_iv	:	128 bit initialisation vector / initial counter value.

Return	:	Decrypted buffer.
"""
static func decrypt_ctr_raw(a_in:PoolByteArray, a_ky:PoolByteArray, a_iv:PoolByteArray) -> PoolByteArray:
	return encrypt_ctr_raw(a_in, a_ky, a_iv)

# ==============================================================================
# AES block cipher implementation (private)

const _SBOX:PoolByteArray = PoolByteArray([
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
])

const _RSBOX:PoolByteArray = PoolByteArray([
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
])

const _RCON:PoolByteArray = PoolByteArray([
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]);

class _AESBlockCipher:
	const _nb:int	= 4		# number of columns comprising a state (constant in AES)
	var   _nk:int			# number of 32 bit words in a key
	var   _nr:int			# number of rounds

	# round keys
	var _RK:PoolByteArray	= PoolByteArray()

	# state
	var _ST:PoolByteArray	= PoolByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])

	func _init(a_ky:PoolByteArray) -> void:
		assert(a_ky.size() == 32 || a_ky.size() == 24 || a_ky.size() == 16)

		# initialise round key storage to max required
		_RK.resize(256)
		for i in range(_RK.size()): _RK[i] = 0

		# initalise AES parameters
		if (a_ky.size() == 32):
			# AES-256
			_nk = 8
			_nr = 14
		elif (a_ky.size() == 24):
			# AES-192
			_nk = 6
			_nr = 12
		else:
			# AES-128
			_nk = 4
			_nr = 10

		# expand key
		_expand_key(a_ky)

		return


	func encipher_block(a_blk:PoolByteArray) -> PoolByteArray:
		# copy block to state
		_ST = a_blk

		# add the first round key to the state before starting the rounds
		_add_round_key(0);

		# main round loop
		for r in range(1, _nr):
			_subbytes()
			_shiftrows()
			_mixcolumns()
			_add_round_key(r);

		# final round
		_subbytes()
		_shiftrows()
		_add_round_key(_nr);

		# return encrypted block
		return _ST

	func decipher_block(a_blk:PoolByteArray) -> PoolByteArray:
		# copy block to state
		_ST = a_blk

		# add the first round key to the state before starting the rounds
		_add_round_key(_nr);

		for r in range(_nr-1, 0, -1):
			_inv_shiftrows()
			_inv_subbytes()
			_add_round_key(r);
			_inv_mixcolumns()
			pass

		# final round
		_inv_shiftrows()
		_inv_subbytes()
		_add_round_key(0);

		# return decrypted block
		return _ST


	# initial key expansion
	func _expand_key(a_ky:PoolByteArray) -> void:
		var j:int
		var k:int
		var t:int
		var temp:PoolByteArray = PoolByteArray([0,0,0,0])

		# The first round key is the key itself
		for i in range(_nk):
			j = i<<2
			_RK[j  ] = a_ky[j  ]
			_RK[j+1] = a_ky[j+1]
			_RK[j+2] = a_ky[j+2]
			_RK[j+3] = a_ky[j+3]

		# All other round keys are found from the previous round keys
		for i in range(_nk, _nb * (_nr+1)):
			j = (i-1) << 2
			temp[0] = _RK[j  ]
			temp[1] = _RK[j+1]
			temp[2] = _RK[j+2]
			temp[3] = _RK[j+3]

			if (i % _nk == 0):
				# shifts the 4 bytes in a word to the left once.
				# [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
				t       = temp[0]
				temp[0] = temp[1]
				temp[1] = temp[2]
				temp[2] = temp[3]
				temp[3] = t

				# SubWord() is a function that takes a four-byte input word and
				# applies the S-box to each of the four bytes to produce an output word
				temp[0] = _SBOX[temp[0]]
				temp[1] = _SBOX[temp[1]]
				temp[2] = _SBOX[temp[2]]
				temp[3] = _SBOX[temp[3]]

				# warning-ignore:integer_division
				temp[0] = temp[0] ^ _RCON[i/_nk]

			if (a_ky.size() == 32 && i % _nk == 4):
				temp[0] = _SBOX[temp[0]]
				temp[1] = _SBOX[temp[1]]
				temp[2] = _SBOX[temp[2]]
				temp[3] = _SBOX[temp[3]]

			j = i << 2
			k = (i - _nk) << 2
			_RK[j  ] = _RK[k  ] ^ temp[0]
			_RK[j+1] = _RK[k+1] ^ temp[1]
			_RK[j+2] = _RK[k+2] ^ temp[2]
			_RK[j+3] = _RK[k+3] ^ temp[3]

		return

	# xor a round key into state
	func _add_round_key(a_round:int) -> void:
		var p:int = a_round << 4	# <<4 is *16 = 4*_nb where _nb is a constant=4
		_ST[ 0] ^= _RK[p   ]
		_ST[ 1] ^= _RK[p+ 1]
		_ST[ 2] ^= _RK[p+ 2]
		_ST[ 3] ^= _RK[p+ 3]
		_ST[ 4] ^= _RK[p+ 4]
		_ST[ 5] ^= _RK[p+ 5]
		_ST[ 6] ^= _RK[p+ 6]
		_ST[ 7] ^= _RK[p+ 7]
		_ST[ 8] ^= _RK[p+ 8]
		_ST[ 9] ^= _RK[p+ 9]
		_ST[10] ^= _RK[p+10]
		_ST[11] ^= _RK[p+11]
		_ST[12] ^= _RK[p+12]
		_ST[13] ^= _RK[p+13]
		_ST[14] ^= _RK[p+14]
		_ST[15] ^= _RK[p+15]
		return

	# substitutes state values with sbox values
	func _subbytes() -> void:
		_ST[ 0] = _SBOX[_ST[ 0]]
		_ST[ 4] = _SBOX[_ST[ 4]]
		_ST[ 8] = _SBOX[_ST[ 8]]
		_ST[12] = _SBOX[_ST[12]]

		_ST[ 1] = _SBOX[_ST[ 1]]
		_ST[ 5] = _SBOX[_ST[ 5]]
		_ST[ 9] = _SBOX[_ST[ 9]]
		_ST[13] = _SBOX[_ST[13]]

		_ST[ 2] = _SBOX[_ST[ 2]]
		_ST[ 6] = _SBOX[_ST[ 6]]
		_ST[10] = _SBOX[_ST[10]]
		_ST[14] = _SBOX[_ST[14]]

		_ST[ 3] = _SBOX[_ST[ 3]]
		_ST[ 7] = _SBOX[_ST[ 7]]
		_ST[11] = _SBOX[_ST[11]]
		_ST[15] = _SBOX[_ST[15]]

		return

	func _inv_subbytes() -> void:
		_ST[ 0] = _RSBOX[_ST[ 0]]
		_ST[ 4] = _RSBOX[_ST[ 4]]
		_ST[ 8] = _RSBOX[_ST[ 8]]
		_ST[12] = _RSBOX[_ST[12]]

		_ST[ 1] = _RSBOX[_ST[ 1]]
		_ST[ 5] = _RSBOX[_ST[ 5]]
		_ST[ 9] = _RSBOX[_ST[ 9]]
		_ST[13] = _RSBOX[_ST[13]]

		_ST[ 2] = _RSBOX[_ST[ 2]]
		_ST[ 6] = _RSBOX[_ST[ 6]]
		_ST[10] = _RSBOX[_ST[10]]
		_ST[14] = _RSBOX[_ST[14]]

		_ST[ 3] = _RSBOX[_ST[ 3]]
		_ST[ 7] = _RSBOX[_ST[ 7]]
		_ST[11] = _RSBOX[_ST[11]]
		_ST[15] = _RSBOX[_ST[15]]
		return

	# rotate state rows
	func _shiftrows() -> void:
		var t:int

		# rotate first row 1 columns to left
		t       = _ST[ 1]
		_ST[ 1] = _ST[ 5]
		_ST[ 5] = _ST[ 9]
		_ST[ 9] = _ST[13]
		_ST[13] = t

		# rotate second row 2 columns to left
		t       = _ST[ 2]
		_ST[ 2] = _ST[10]
		_ST[10] = t

		t       = _ST[ 6]
		_ST[ 6] = _ST[14]
		_ST[14] = t

		# rotate third row 3 columns to left
		t       = _ST[ 3]
		_ST[ 3] = _ST[15]
		_ST[15] = _ST[11]
		_ST[11] = _ST[ 7]
		_ST[ 7] = t

		return

	func _inv_shiftrows() -> void:
		var t:int

		# rotate first row 1 columns to right
		t       = _ST[13]
		_ST[13] = _ST[ 9]
		_ST[ 9] = _ST[ 5]
		_ST[ 5] = _ST[ 1]
		_ST[ 1] = t

		# rotate second row 2 columns to right
		t       = _ST[ 2]
		_ST[ 2] = _ST[10]
		_ST[10] = t

		t       = _ST[ 6]
		_ST [6] = _ST[14]
		_ST[14] = t

		# rotate third row 3 columns to right
		t       = _ST[ 3]
		_ST[ 3] = _ST[ 7]
		_ST[ 7] = _ST[11]
		_ST[11] = _ST[15]
		_ST[15] = t

		return

	# mix state columns
	func _xtime(x:int) -> int:
		x &= 0xff;
		return ( ((x<<1) & 0xff) ^ (((x>>7) & 1) * 0x1b) ) & 0xff

	func _mul(x:int, y:int) -> int:
		x &= 0xff
		y &= 0xff
		return (
			((y    & 1) * x) ^
			((y>>1 & 1) * _xtime(x)) ^
			((y>>2 & 1) * _xtime(_xtime(x))) ^
			((y>>3 & 1) * _xtime(_xtime(_xtime(x)))) ^
			((y>>4 & 1) * _xtime(_xtime(_xtime(_xtime(x)))))
		) & 0xff

	func _mixcolumns() -> void:
		var a:int
		var b:int
		var c:int
		var i4:int
		for i in range(4):
			i4 = i<<2

			c = _ST[i4  ]
			a = _ST[i4  ] ^ _ST[i4+1] ^ _ST[i4+2] ^ _ST[i4+3]
			b = _ST[i4  ] ^ _ST[i4+1] ; b = _xtime(b); _ST[i4  ] ^= b ^ a
			b = _ST[i4+1] ^ _ST[i4+2] ; b = _xtime(b); _ST[i4+1] ^= b ^ a
			b = _ST[i4+2] ^ _ST[i4+3] ; b = _xtime(b); _ST[i4+2] ^= b ^ a
			b = _ST[i4+3] ^ c         ; b = _xtime(b); _ST[i4+3] ^= b ^ a
		return

	func _inv_mixcolumns() -> void:
		var a:int
		var b:int
		var c:int
		var d:int
		var i4:int
		for i in range(4):
			i4 = i<<2

			a = _ST[i4  ];
			b = _ST[i4+1];
			c = _ST[i4+2];
			d = _ST[i4+3];

			_ST[i4  ] = _mul(a, 0x0e) ^ _mul(b, 0x0b) ^ _mul(c, 0x0d) ^ _mul(d, 0x09);
			_ST[i4+1] = _mul(a, 0x09) ^ _mul(b, 0x0e) ^ _mul(c, 0x0b) ^ _mul(d, 0x0d);
			_ST[i4+2] = _mul(a, 0x0d) ^ _mul(b, 0x09) ^ _mul(c, 0x0e) ^ _mul(d, 0x0b);
			_ST[i4+3] = _mul(a, 0x0b) ^ _mul(b, 0x0d) ^ _mul(c, 0x09) ^ _mul(d, 0x0e);
		return

# ==============================================================================



