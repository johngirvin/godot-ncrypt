# ==============================================================================
# NCryptTest - test suite for NCrypt
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
class_name NCryptTest

# ==============================================================================
# VARIABLES

# plaintext
var P:PoolByteArray

# keys and ivs, indexed by bit length
const A:Dictionary = { }

# scratch variables used by tests
var tv:Array
var ky:PoolByteArray
var iv:PoolByteArray
var pt:PoolByteArray
var ec:PoolByteArray

# ==============================================================================
# NCryptTest

func _init() -> void:
	# generate key and iv buffers
	for i in [ 64, 96, 128, 192, 256, 384, 512, 1024, 2048 ]:
		var ib:int = i>>3

		var a:PoolByteArray = PoolByteArray()
		a.resize(ib)
		for j in range(ib): a[j] = 0x80 if (j == 0) else 0x00

		A[i] = a

	# generate source plaintext
	# p0 is 512 ASCII bytes of Bacon Ipsum https://baconipsum.com
	var p0:PoolByteArray = 'Meatloaf turducken spare ribs, chuck aute lorem voluptate venison anim est excepteur pork aliquip hamburger. Tongue ribeye cillum anim sirloin pastrami bacon deserunt pork chop alcatra ground round sunt. Adipisicing in chuck bresaola id. Andouille proident turducken, pork chop labore chuck brisket shankle spare ribs capicola commodo voluptate rump in kielbasa. Ad tongue officia cupidatat, corned beef doner swine velit cupim. Shankle flank culpa short loin pig, pork belly pork chop. Pastrami aliqu deserunt. '.to_ascii()
	for i in range(32768/p0.size()):
		P.append_array(p0)
	assert(P.size() == 32768)

	return

func _pba_equal(a:PoolByteArray, b:PoolByteArray) -> bool:
	if (a.size() != b.size()): return false
	for i in range(a.size()):
		if (a[i] != b[i]): return false
	return true

# ==============================================================================

func run_all_tests() -> void:
	# test basics
	print('test_hex_to_raw')
	test_hex_to_raw()

	print('test_raw_to_hex')
	test_raw_to_hex()

	print('test_rotl32')
	test_rotl32()

	print('test_rotr32')
	test_rotr32()

	print('test_rotl64')
	test_rotl64()

	# test pads
	print('test_pkcs5')
	test_pkcs5()


	# test ciphers
	print('test_aes')
	test_aes()

	print('test_arcfour')
	test_arcfour()

	print('test_chacha')
	test_chacha()


	# test hashes/macs
	print('test_sha256')
	test_sha256()

	print('test_hmac_sha256')
	test_hmac_sha256()
	
	print('test_siphash')
	test_siphash()
	
	
	# test prng
	print('test_prng')
	test_prng()
	
	# all ok
	return
	
# ==============================================================================
# TESTS

func test_hex_to_raw() -> void:
	var r:PoolByteArray = NCrypt.hex_to_raw('11')
	assert(r.size() == 1)
	assert(r[0]     == 0x11)
	
	r = NCrypt.hex_to_raw('11223344')
	assert(r.size() == 4)
	assert(r[0]     == 0x11)
	assert(r[1]     == 0x22)
	assert(r[2]     == 0x33)
	assert(r[3]     == 0x44)

	r = NCrypt.hex_to_raw('11223344aabbccdd')
	assert(r.size() == 8)
	assert(r[0]     == 0x11)
	assert(r[1]     == 0x22)
	assert(r[2]     == 0x33)
	assert(r[3]     == 0x44)
	assert(r[4]     == 0xaa)
	assert(r[5]     == 0xbb)
	assert(r[6]     == 0xcc)
	assert(r[7]     == 0xdd)

	r = NCrypt.hex_to_raw('11223344aabbccdd99')
	assert(r.size() == 9)
	assert(r[0]     == 0x11)
	assert(r[1]     == 0x22)
	assert(r[2]     == 0x33)
	assert(r[3]     == 0x44)
	assert(r[4]     == 0xaa)
	assert(r[5]     == 0xbb)
	assert(r[6]     == 0xcc)
	assert(r[7]     == 0xdd)
	assert(r[8]     == 0x99)
	
	return

func test_raw_to_hex() -> void:
	var s:String = NCrypt.raw_to_hex(PoolByteArray([ 0x11 ]))
	assert(s == '11')
	
	s = NCrypt.raw_to_hex(PoolByteArray([ 0x11, 0x22, 0x33, 0x44 ]))
	assert(s == '11223344')

	s = NCrypt.raw_to_hex(PoolByteArray([ 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd ]))
	assert(s == '11223344aabbccdd')

	s = NCrypt.raw_to_hex(PoolByteArray([ 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x99 ]))
	assert(s == '11223344aabbccdd99')
	
	return

func test_rotl32() -> void:
	for r in range(0,32):
		assert(NCrypt.rotl32(0x00000001, r)) == (0x00000001 << r)
		assert(NCrypt.rotl32(0x00000000, r)) == 0x00000000
		
	assert(NCrypt.rotl32(0x80000001,  0)) == 0x80000001
	assert(NCrypt.rotl32(0x80000001, 32)) == 0x80000001
	
	assert(NCrypt.rotl32(0xff000000, 1)) == 0xfe000001
	
	return

func test_rotr32() -> void:
	for r in range(0,32):
		assert(NCrypt.rotr32(0x80000000, r)) == (0x80000000 >> r)
		assert(NCrypt.rotr32(0x00000000, r)) == 0x00000000
		
	assert(NCrypt.rotr32(0x80000001,  0)) == 0x80000001
	assert(NCrypt.rotr32(0x80000001, 32)) == 0x80000001
	
	assert(NCrypt.rotr32(0x000000ff,  1)) == 0x8000007f
	
	return

func test_rotl64() -> void:
	for r in range(0,64):
		assert(NCrypt.rotl64(1, r)) == (1 << r)
		assert(NCrypt.rotl64(0, r)) == 0

	assert(NCrypt.rotl64(0x8000000000000001,  0)) == 0x8000000000000001
	assert(NCrypt.rotl64(0x8000000000000001, 64)) == 0x8000000000000001

	assert(NCrypt.rotl64(0xff00000000000000,  1)) == 0xfe00000000000001
	
	return
	
# ==============================================================================

func test_pkcs5() -> void:
	# test pad/unpad pairs
	for pl in [ 4, 8, 16, 24, 32, 64 ]:
		for i in [ -1, -2, -3 ]:
			pt = P.subarray(0,pl+i)
			assert(_pba_equal(pt, PKCS5.unpad(PKCS5.pad(pt,pl))))
		
	# test vectors
	tv = [
		'aa',
		4,
		'aa030303',

		'bbbbbb',
		4,
		'bbbbbb01',

		'cccccccc',
		4,
		'cccccccc04040404',
	]
	
	var pd:int
	for i in range(0, tv.size(), 3):
		pt = NCrypt.hex_to_raw(tv[i])
		ec = NCrypt.hex_to_raw(tv[i+2])
		assert(_pba_equal(ec, PKCS5.pad(pt, tv[i+1])))
		
	return
	 	
# ==============================================================================

func test_aes() -> void:
	# test encrypt/decrypt pairs
	for kl in [ 128, 192, 256 ]:
		for pl in [ 16, 32, 1024 ]:
			pt = P.subarray(0,pl-1)
			# raw
			assert(_pba_equal(pt, AES.decrypt_ecb_raw(AES.encrypt_ecb_raw(pt, A[kl]        ), A[kl]        )))
			assert(_pba_equal(pt, AES.decrypt_cbc_raw(AES.encrypt_cbc_raw(pt, A[kl], A[128]), A[kl], A[128])))
			assert(_pba_equal(pt, AES.decrypt_ctr_raw(AES.encrypt_ctr_raw(pt, A[kl], A[128]), A[kl], A[128])))
			# hex
			assert(_pba_equal(pt, AES.decrypt_ecb_hex(AES.encrypt_ecb_hex(pt, A[kl]        ), A[kl]        )))
			assert(_pba_equal(pt, AES.decrypt_cbc_hex(AES.encrypt_cbc_hex(pt, A[kl], A[128]), A[kl], A[128])))
			assert(_pba_equal(pt, AES.decrypt_ctr_hex(AES.encrypt_ctr_hex(pt, A[kl], A[128]), A[kl], A[128])))
			# base64
			assert(_pba_equal(pt, AES.decrypt_ecb_base64(AES.encrypt_ecb_base64(pt, A[kl]        ), A[kl]        )))
			assert(_pba_equal(pt, AES.decrypt_cbc_base64(AES.encrypt_cbc_base64(pt, A[kl], A[128]), A[kl], A[128])))
			assert(_pba_equal(pt, AES.decrypt_ctr_base64(AES.encrypt_ctr_base64(pt, A[kl], A[128]), A[kl], A[128])))
	
	# test vectors ecb
	# source: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	tv = [
		'2b7e151628aed2a6abf7158809cf4f3c',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4',

		'8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e',

		'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7'
	]
	for i in range(0, tv.size(), 3):
		ky = NCrypt.hex_to_raw(tv[i])
		pt = NCrypt.hex_to_raw(tv[i+1])
		ec = NCrypt.hex_to_raw(tv[i+2])
		assert(_pba_equal(ec, AES.encrypt_ecb_raw(pt, ky)))
		assert(_pba_equal(pt, AES.decrypt_ecb_raw(ec, ky)))
		
		ky[0] ^= 0x55
		assert(!_pba_equal(ec, AES.encrypt_ecb_raw(pt, ky)))
		assert(!_pba_equal(pt, AES.decrypt_ecb_raw(ec, ky)))
		
	# test vectors cbc
	# source: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	tv = [
		'2b7e151628aed2a6abf7158809cf4f3c',
		'000102030405060708090a0b0c0d0e0f',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7',
		
		'8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		'000102030405060708090a0b0c0d0e0f',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd',
		
		'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		'000102030405060708090a0b0c0d0e0f',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b'
	]
	for i in range(0, tv.size(), 4):
		ky = NCrypt.hex_to_raw(tv[i])
		iv = NCrypt.hex_to_raw(tv[i+1])
		pt = NCrypt.hex_to_raw(tv[i+2])
		ec = NCrypt.hex_to_raw(tv[i+3])
		assert(_pba_equal(ec, AES.encrypt_cbc_raw(pt, ky, iv)))
		assert(_pba_equal(pt, AES.decrypt_cbc_raw(ec, ky, iv)))
		
		ky[0] ^= 0x55
		assert(!_pba_equal(ec, AES.encrypt_cbc_raw(pt, ky, iv)))
		assert(!_pba_equal(pt, AES.decrypt_cbc_raw(ec, ky, iv)))
		ky[0] ^= 0x55
		
		iv[0] ^= 0x55
		assert(!_pba_equal(ec, AES.encrypt_cbc_raw(pt, ky, iv)))
		assert(!_pba_equal(pt, AES.decrypt_cbc_raw(ec, ky, iv)))
		
	# test vectors ctr
	# source: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	tv = [
		'2b7e151628aed2a6abf7158809cf4f3c',
		'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee',

		'8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050',

		'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
		'601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6'
	]
	for i in range(0, tv.size(), 4):
		ky = NCrypt.hex_to_raw(tv[i])
		iv = NCrypt.hex_to_raw(tv[i+1])
		pt = NCrypt.hex_to_raw(tv[i+2])
		ec = NCrypt.hex_to_raw(tv[i+3])
		assert(_pba_equal(ec, AES.encrypt_ctr_raw(pt, ky, iv)))
		assert(_pba_equal(pt, AES.decrypt_ctr_raw(ec, ky, iv)))

		ky[0] ^= 0x55
		assert(!_pba_equal(ec, AES.encrypt_ctr_raw(pt, ky, iv)))
		assert(!_pba_equal(pt, AES.decrypt_ctr_raw(ec, ky, iv)))
		ky[0] ^= 0x55
		
		iv[0] ^= 0x55
		assert(!_pba_equal(ec, AES.encrypt_ctr_raw(pt, ky, iv)))
		assert(!_pba_equal(pt, AES.decrypt_ctr_raw(ec, ky, iv)))
		
	return
	
# ==============================================================================

func test_arcfour() -> void:
	# test encrypt/decrypt pairs
	for kl in [ 256, 512, 1024, 2048 ]:
		for dl in [ 0, 512, 3072 ]:
			for pl in [ 16, 32, 1024, 2053 ]:
				pt = P.subarray(0,pl-1)
				assert(_pba_equal(pt, ARCFOUR.decrypt_raw(ARCFOUR.encrypt_raw(pt, A[kl], dl), A[kl], dl)))
				assert(_pba_equal(pt, ARCFOUR.decrypt_hex(ARCFOUR.encrypt_hex(pt, A[kl], dl), A[kl], dl)))
				assert(_pba_equal(pt, ARCFOUR.decrypt_base64(ARCFOUR.encrypt_base64(pt, A[kl], dl), A[kl], dl)))
	
	# test vectors
	# source: https://en.wikipedia.org/wiki/RC4#Test_vectors
	tv = [
		NCrypt.raw_to_hex('Key'.to_ascii()),
		NCrypt.raw_to_hex('Plaintext'.to_ascii()),
		'BBF316E8D940AF0AD3',
		
		NCrypt.raw_to_hex('Wiki'.to_ascii()),
		NCrypt.raw_to_hex('pedia'.to_ascii()),
		'1021BF0420',
		
		NCrypt.raw_to_hex('Secret'.to_ascii()),
		NCrypt.raw_to_hex('Attack at dawn'.to_ascii()),
		'45A01F645FC35B383552544B9BF5'
	]
	for i in range(0, tv.size(), 3):
		ky = NCrypt.hex_to_raw(tv[i])
		pt = NCrypt.hex_to_raw(tv[i+1])
		ec = NCrypt.hex_to_raw(tv[i+2])
		assert(_pba_equal(ec, ARCFOUR.encrypt_raw(pt, ky)))
		assert(_pba_equal(pt, ARCFOUR.decrypt_raw(ec, ky)))
		
		ky[0] ^= 0x55
		assert(!_pba_equal(ec, ARCFOUR.encrypt_raw(pt, ky)))
		assert(!_pba_equal(pt, ARCFOUR.decrypt_raw(ec, ky)))
	
	return

# ==============================================================================
	
func test_chacha() -> void:
	# test encrypt/decrypt pairs
	for kl in [ 128, 256 ]:
		for il in [ 64, 96 ]:
			for rc in [ 8, 12, 20 ]:
				for pl in [ 16, 32, 1024, 2053 ]:
					pt = P.subarray(0,pl-1)
					assert(_pba_equal(pt, CHACHA.decrypt_raw(CHACHA.encrypt_raw(pt, A[kl], A[il], 1, rc), A[kl], A[il], 1, rc)))
					assert(_pba_equal(pt, CHACHA.decrypt_hex(CHACHA.encrypt_hex(pt, A[kl], A[il], 1, rc), A[kl], A[il], 1, rc)))
					assert(_pba_equal(pt, CHACHA.decrypt_base64(CHACHA.encrypt_base64(pt, A[kl], A[il], 1, rc), A[kl], A[il], 1, rc)))
	
	# test vector chacha20
	# source: https://tools.ietf.org/html/rfc7539
	tv = [
		'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		'000000000000004a00000000',
		1,
		NCrypt.raw_to_hex('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.'.to_ascii()),
		'6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d',
	
		'0000000000000000000000000000000000000000000000000000000000000000',
		'0000000000000000',
		0,
		'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
		'76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
		
		'0000000000000000000000000000000000000000000000000000000000000001',
		'000000000000000000000002',
		1,
		'416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f',
		'a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221',
		
		'0000000000000000000000000000000000000000000000000000000000000001',
		'000000000000000000000002',
		1,
		'416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f',
		'a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221'
	]
	for i in range(0, tv.size(), 5):
		ky = NCrypt.hex_to_raw(tv[i])
		iv = NCrypt.hex_to_raw(tv[i+1])
		pt = NCrypt.hex_to_raw(tv[i+3])
		ec = NCrypt.hex_to_raw(tv[i+4])
		assert(_pba_equal(ec, CHACHA.encrypt_raw(pt, ky, iv, tv[i+2], 20)))
		assert(_pba_equal(pt, CHACHA.decrypt_raw(ec, ky, iv, tv[i+2], 20)))

		ky[0] ^= 0x55
		assert(!_pba_equal(ec, CHACHA.encrypt_raw(pt, ky, iv, tv[i+2], 20)))
		assert(!_pba_equal(pt, CHACHA.decrypt_raw(ec, ky, iv, tv[i+2], 20)))
		ky[0] ^= 0x55
		
		iv[0] ^= 0x55
		assert(!_pba_equal(ec, CHACHA.encrypt_raw(pt, ky, iv, tv[i+2], 20)))
		assert(!_pba_equal(pt, CHACHA.decrypt_raw(ec, ky, iv, tv[i+2], 20)))
		iv[0] ^= 0x55

		assert(!_pba_equal(ec, CHACHA.encrypt_raw(pt, ky, iv, tv[i+2]+1, 20)))
		assert(!_pba_equal(pt, CHACHA.decrypt_raw(ec, ky, iv, tv[i+2]+1, 20)))

		assert(!_pba_equal(ec, CHACHA.encrypt_raw(pt, ky, iv, tv[i+2], 12)))
		assert(!_pba_equal(pt, CHACHA.decrypt_raw(ec, ky, iv, tv[i+2], 12)))
		
	return

# ==============================================================================

func test_sha256() -> void:
	# test vectors sha256
	tv = [
		'',
		'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',

		'd3',
		'28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1',

		'11af',
		'5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98',

		'b4190e',
		'dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2',

		'74ba2521',
		'b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e',

		'c299209682',
		'f0887fe961c9cd3beab957e8222494abb969b1ce4c6557976df8b0f6d20e9166',

		'e1dc724d5621',
		'eca0a060b489636225b4fa64d267dabbe44273067ac679f20820bddc6b6a90ac',

		'06e076f5a442d5',
		'3fd877e27450e6bbd5d74bb82f9870c64c66e109418baa8e6bbcff355e287926',

		'5738c929c4f4ccb6',
		'963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf',

		'3334c58075d3f4139e',
		'078da3d77ed43bd3037a433fd0341855023793f9afd08b4b08ea1e5597ceef20',

		'74cb9381d89f5aa73368',
		'73d6fad1caaa75b43b21733561fd3958bdc555194a037c2addec19dc2d7a52bd',

		'76ed24a0f40a41221ebfcf',
		'044cef802901932e46dc46b2545e6c99c0fc323a0ed99b081bda4216857f38ac',

		'9baf69cba317f422fe26a9a0',
		'fe56287cd657e4afc50dba7a3a54c2a6324b886becdcd1fae473b769e551a09b',

		'68511cdb2dbbf3530d7fb61cbc',
		'af53430466715e99a602fc9f5945719b04dd24267e6a98471f7a7869bd3b4313',

		'af397a8b8dd73ab702ce8e53aa9f',
		'd189498a3463b18e846b8ab1b41583b0b7efc789dad8a7fb885bbf8fb5b45c5c',

		'294af4802e5e925eb1c6cc9c724f09',
		'dcbaf335360de853b9cddfdafb90fa75567d0d3d58af8db9d764113aef570125',

		'0a27847cdc98bd6f62220b046edd762b',
		'80c25ec1600587e7f28b18b1b18e3cdc89928e39cab3bc25e4d4a4c139bcedc4',

		'1b503fb9a73b16ada3fcf1042623ae7610',
		'd5c30315f72ed05fe519a1bf75ab5fd0ffec5ac1acb0daf66b6b769598594509',

		'59eb45bbbeb054b0b97334d53580ce03f699',
		'32c38c54189f2357e96bd77eb00c2b9c341ebebacc2945f97804f59a93238288',

		'58e5a3259cb0b6d12c83f723379e35fd298b60',
		'9b5b37816de8fcdf3ec10b745428708df8f391c550ea6746b2cafe019c2b6ace',

		'c1ef39cee58e78f6fcdc12e058b7f902acd1a93b',
		'6dd52b0d8b48cc8146cebd0216fbf5f6ef7eeafc0ff2ff9d1422d6345555a142',

		'9cab7d7dcaec98cb3ac6c64dd5d4470d0b103a810c',
		'44d34809fc60d1fcafa7f37b794d1d3a765dd0d23194ebbe340f013f0c39b613',

		'ea157c02ebaf1b22de221b53f2353936d2359d1e1c97',
		'9df5c16a3f580406f07d96149303d8c408869b32053b726cf3defd241e484957',

		'da999bc1f9c7acff32828a73e672d0a492f6ee895c6867',
		'672b54e43f41ee77584bdf8bf854d97b6252c918f7ea2d26bc4097ea53a88f10',

		'47991301156d1d977c0338efbcad41004133aefbca6bcf7e',
		'feeb4b2b59fec8fdb1e55194a493d8c871757b5723675e93d3ac034b380b7fc9',

		'2e7ea84da4bc4d7cfb463e3f2c8647057afff3fbececa1d200',
		'76e3acbc718836f2df8ad2d0d2d76f0cfa5fea0986be918f10bcee730df441b9',

		'47c770eb4549b6eff6381d62e9beb464cd98d341cc1c09981a7a',
		'6733809c73e53666c735b3bd3daf87ebc77c72756150a616a194108d71231272',

		'ac4c26d8b43b8579d8f61c9807026e83e9b586e1159bd43b851937',
		'0e6e3c143c3a5f7f38505ed6adc9b48c18edf6dedf11635f6e8f9ac73c39fe9e',

		'0777fc1e1ca47304c2e265692838109e26aab9e5c4ae4e8600df4b1f',
		'ffb4fc03e054f8ecbc31470fc023bedcd4a406b9dd56c71da1b660dcc4842c65',

		'1a57251c431d4e6c2e06d65246a296915071a531425ecf255989422a66',
		'c644612cd326b38b1c6813b1daded34448805aef317c35f548dfb4a0d74b8106',

		'9b245fdad9baeb890d9c0d0eff816efb4ca138610bc7d78cb1a801ed3273',
		'c0e29eeeb0d3a7707947e623cdc7d1899adc70dd7861205ea5e5813954fb7957',

		'95a765809caf30ada90ad6d61c2b4b30250df0a7ce23b7753c9187f4319ce2',
		'a4139b74b102cf1e2fce229a6cd84c87501f50afa4c80feacf7d8cf5ed94f042',

		'09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95',
		'4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4',

		'0546f7b8682b5b95fd32385faf25854cb3f7b40cc8fa229fbd52b16934aab388a7',
		'b31ad3cd02b10db282b3576c059b746fb24ca6f09fef69402dc90ece7421cbb7',

		'b12db4a1025529b3b7b1e45c6dbc7baa8897a0576e66f64bf3f8236113a6276ee77d',
		'1c38bf6bbfd32292d67d1d651fd9d5b623b6ec1e854406223f51d0df46968712',

		'e68cb6d8c1866c0a71e7313f83dc11a5809cf5cfbeed1a587ce9c2c92e022abc1644bb',
		'c2684c0dbb85c232b6da4fb5147dd0624429ec7e657991edd95eda37a587269e',

		'4e3d8ac36d61d9e51480831155b253b37969fe7ef49db3b39926f3a00b69a36774366000',
		'bf9d5e5b5393053f055b380baed7e792ae85ad37c0ada5fd4519542ccc461cf3',

		'03b264be51e4b941864f9b70b4c958f5355aac294b4b87cb037f11f85f07eb57b3f0b89550',
		'd1f8bd684001ac5a4b67bbf79f87de524d2da99ac014dec3e4187728f4557471',

		'd0fefd96787c65ffa7f910d6d0ada63d64d5c4679960e7f06aeb8c70dfef954f8e39efdb629b',
		'49ba38db85c2796f85ffd57dd5ec337007414528ae33935b102d16a6b91ba6c1',

		'b7c79d7e5f1eeccdfedf0e7bf43e730d447e607d8d1489823d09e11201a0b1258039e7bd4875b1',
		'725e6f8d888ebaf908b7692259ab8839c3248edd22ca115bb13e025808654700',

		'64cd363ecce05fdfda2486d011a3db95b5206a19d3054046819dd0d36783955d7e5bf8ba18bf738a',
		'32caef024f84e97c30b4a7b9d04b678b3d8a6eb2259dff5b7f7c011f090845f8',

		'6ac6c63d618eaf00d91c5e2807e83c093912b8e202f78e139703498a79c6067f54497c6127a23910a6',
		'4bb33e7c6916e08a9b3ed6bcef790aaaee0dcf2e7a01afb056182dea2dad7d63',

		'd26826db9baeaa892691b68900b96163208e806a1da077429e454fa011840951a031327e605ab82ecce2',
		'3ac7ac6bed82fdc8cd15b746f0ee7489158192c238f371c1883c9fe90b3e2831',

		'3f7a059b65d6cb0249204aac10b9f1a4ac9e5868adebbe935a9eb5b9019e1c938bfc4e5c5378997a3947f2',
		'bfce809534eefe871273964d32f091fe756c71a7f512ef5f2300bcd57f699e74',

		'60ffcb23d6b88e485b920af81d1083f6291d06ac8ca3a965b85914bc2add40544a027fca936bbde8f359051c',
		'1d26f3e04f89b4eaa9dbed9231bb051eef2e8311ad26fe53d0bf0b821eaf7567',

		'9ecd07b684bb9e0e6692e320cec4510ca79fcdb3a2212c26d90df65db33e692d073cc174840db797504e482eef',
		'0ffeb644a49e787ccc6970fe29705a4f4c2bfcfe7d19741c158333ff6982cc9c',

		'9d64de7161895884e7fa3d6e9eb996e7ebe511b01fe19cd4a6b3322e80aaf52bf6447ed1854e71001f4d54f8931d',
		'd048ee1524014adf9a56e60a388277de194c694cc787fc5a1b554ea9f07abfdf',

		'c4ad3c5e78d917ecb0cbbcd1c481fc2aaf232f7e289779f40e504cc309662ee96fecbd20647ef00e46199fbc482f46',
		'50dbf40066f8d270484ee2ef6632282dfa300a85a8530eceeb0e04275e1c1efd',

		'4eef5107459bddf8f24fc7656fd4896da8711db50400c0164847f692b886ce8d7f4d67395090b3534efd7b0d298da34b',
		'7c5d14ed83dab875ac25ce7feed6ef837d58e79dc601fb3c1fca48d4464e8b83',

		'047d2758e7c2c9623f9bdb93b6597c5e84a0cd34e610014bcb25b49ed05c7e356e98c7a672c3dddcaeb84317ef614d342f',
		'7d53eccd03da37bf58c1962a8f0f708a5c5c447f6a7e9e26137c169d5bdd82e4',

		'3d83df37172c81afd0de115139fbf4390c22e098c5af4c5ab4852406510bc0e6cf741769f44430c5270fdae0cb849d71cbab',
		'99dc772e91ea02d9e421d552d61901016b9fd4ad2df4a8212c1ec5ba13893ab2',

		'33fd9bc17e2b271fa04c6b93c0bdeae98654a7682d31d9b4dab7e6f32cd58f2f148a68fbe7a88c5ab1d88edccddeb30ab21e5e',
		'cefdae1a3d75e792e8698d5e71f177cc761314e9ad5df9602c6e60ae65c4c267',

		'77a879cfa11d7fcac7a8282cc38a43dcf37643cc909837213bd6fd95d956b219a1406cbe73c52cd56c600e55b75bc37ea69641bc',
		'c99d64fa4dadd4bc8a389531c68b4590c6df0b9099c4d583bc00889fb7b98008',

		'45a3e6b86527f20b4537f5af96cfc5ad8777a2dde6cf7511886c5590ece24fc61b226739d207dabfe32ba6efd9ff4cd5db1bd5ead3',
		'4d12a849047c6acd4b2eee6be35fa9051b02d21d50d419543008c1d82c427072',

		'25362a4b9d74bde6128c4fdc672305900947bc3ada9d9d316ebcf1667ad4363189937251f149c72e064a48608d940b7574b17fefc0df',
		'f8e4ccab6c979229f6066cc0cb0cfa81bb21447c16c68773be7e558e9f9d798d',

		'3ebfb06db8c38d5ba037f1363e118550aad94606e26835a01af05078533cc25f2f39573c04b632f62f68c294ab31f2a3e2a1a0d8c2be51',
		'6595a2ef537a69ba8583dfbf7f5bec0ab1f93ce4c8ee1916eff44a93af5749c4',

		'2d52447d1244d2ebc28650e7b05654bad35b3a68eedc7f8515306b496d75f3e73385dd1b002625024b81a02f2fd6dffb6e6d561cb7d0bd7a',
		'cfb88d6faf2de3a69d36195acec2e255e2af2b7d933997f348e09f6ce5758360',

		'4cace422e4a015a75492b3b3bbfbdf3758eaff4fe504b46a26c90dacc119fa9050f603d2b58b398cad6d6d9fa922a154d9e0bc4389968274b0',
		'4d54b2d284a6794581224e08f675541c8feab6eefa3ac1cfe5da4e03e62f72e4',

		'8620b86fbcaace4ff3c2921b8466ddd7bacae07eefef693cf17762dcabb89a84010fc9a0fb76ce1c26593ad637a61253f224d1b14a05addccabe',
		'dba490256c9720c54c612a5bd1ef573cd51dc12b3e7bd8c6db2eabe0aacb846b',

		'd1be3f13febafefc14414d9fb7f693db16dc1ae270c5b647d80da8583587c1ad8cb8cb01824324411ca5ace3ca22e179a4ff4986f3f21190f3d7f3',
		'02804978eba6e1de65afdbc6a6091ed6b1ecee51e8bff40646a251de6678b7ef',

		'f499cc3f6e3cf7c312ffdfba61b1260c37129c1afb391047193367b7b2edeb579253e51d62ba6d911e7b818ccae1553f6146ea780f78e2219f629309',
		'0b66c8b4fefebc8dc7da0bbedc1114f228aa63c37d5c30e91ab500f3eadfcec5',

		'6dd6efd6f6caa63b729aa8186e308bc1bda06307c05a2c0ae5a3684e6e460811748690dc2b58775967cfcc645fd82064b1279fdca771803db9dca0ff53',
		'c464a7bf6d180de4f744bb2fe5dc27a3f681334ffd54a9814650e60260a478e3',

		'6511a2242ddb273178e19a82c57c85cb05a6887ff2014cf1a31cb9ba5df1695aadb25c22b3c5ed51c10d047d256b8e3442842ae4e6c525f8d7a5a944af2a',
		'd6859c0b5a0b66376a24f56b2ab104286ed0078634ba19112ace0d6d60a9c1ae',

		'e2f76e97606a872e317439f1a03fcd92e632e5bd4e7cbc4e97f1afc19a16fde92d77cbe546416b51640cddb92af996534dfd81edb17c4424cf1ac4d75aceeb',
		'18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23',

		'5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509',
		'42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa'
	]

	for i in range(0, tv.size(), 2):
		pt = NCrypt.hex_to_raw(tv[i])
		ec = NCrypt.hex_to_raw(tv[i+1])
		assert(_pba_equal(ec, SHA256.hash_raw(pt)))
		assert(_pba_equal(ec, NCrypt.hex_to_raw(SHA256.hash_hex(pt))))
		assert(_pba_equal(ec, Marshalls.base64_to_raw(SHA256.hash_base64(pt))))
			
	return
	
# ==============================================================================

func test_hmac_sha256() -> void:
	# test vectors hmac-sha256
	tv = [
		'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		'4869205468657265',
		'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',

		'4a656665',
		'7768617420646f2079612077616e7420666f72206e6f7468696e673f',
		'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',

		'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
		'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
		'773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',

		'0102030405060708090a0b0c0d0e0f10111213141516171819',
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
		'82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',

		'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
		'54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
		'60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',

		'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
		'5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e',
		'9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
	]

	for i in range(0, tv.size(), 3):
		ky = NCrypt.hex_to_raw(tv[i])
		pt = NCrypt.hex_to_raw(tv[i+1])
		ec = NCrypt.hex_to_raw(tv[i+2])
		assert(_pba_equal(ec, HMACSHA256.hmac_raw(pt, ky)))
		assert(_pba_equal(ec, NCrypt.hex_to_raw(HMACSHA256.hmac_hex(pt, ky))))
		assert(_pba_equal(ec, Marshalls.base64_to_raw(HMACSHA256.hmac_base64(pt, ky))))
	
# ==============================================================================

func test_siphash() -> void:
	# set key 00 01 02...
	ky = PoolByteArray()
	for i in range(16): ky.append(i)
	
	pt = PoolByteArray()
	
	# source: https://raw.githubusercontent.com/veorq/SipHash/master/vectors.h
	# SipHash-2-4 64-bit output with key and
	# pt = (empty string)
	# pt = 00
	# pt = 00 01
	# pt = 00 01 02
	# ...
	# pt = 00 01 02 ... 3e
	tv = [
		'310e0edd47db6f72',
		'fd67dc93c539f874',
		'5a4fa9d909806c0d',
		'2d7efbd796666785',
		'b7877127e09427cf',
		'8da699cd64557618',
		'cee3fe586e46c9cb',
		'37d1018bf50002ab',
		'6224939a79f5f593',
		'b0e4a90bdf82009e',
		'f3b9dd94c5bb5d7a',
		'a7ad6b22462fb3f4',
		'fbe50e86bc8f1e75',
		'903d84c02756ea14',
		'eef27a8e90ca23f7',
		'e545be4961ca29a1',
		'db9bc2577fcc2a3f',
		'9447be2cf5e99a69',
		'9cd38d96f0b3c14b',
		'bd6179a71dc96dbb',
		'98eea21af25cd6be',
		'c7673b2eb0cbf2d0',
		'883ea3e395675393',
		'c8ce5ccd8c030ca8',
		'94af49f6c650adb8',
		'eab8858ade92e1bc',
		'f315bb5bb835d817',
		'adcf6b0763612e2f',
		'a5c91da7acaa4dde',
		'716595876650a2a6',
		'28ef495c53a387ad',
		'42c341d8fa92d832',
		'ce7cf2722f512771',
		'e37859f94623f3a7',
		'381205bb1ab0e012',
		'ae97a10fd434e015',
		'b4a31508beff4d31',
		'81396229f0907902',
		'4d0cf49ee5d4dcca',
		'5c73336a76d8bf9a',
		'd0a704536ba93e0e',
		'925958fcd6420cad',
		'a915c29bc8067318',
		'952b79f3bc0aa6d4',
		'f21df2e41d4535f9',
		'87577519048f53a9',
		'10a56cf5dfcd9adb',
		'eb75095ccd986cd0',
		'51a9cb9ecba312e6',
		'96afadfc2ce666c7',
		'72fe52975a4364ee',
		'5a1645b276d592a1',
		'b274cb8ebf87870a',
		'6f9bb4203de7b381',
		'eaecb2a30b22a87f',
		'9924a43cc1315724',
		'bd838d3aafbf8db7',
		'0b1a2a3265d51aea',
		'135079a3231ce660',
		'932b2846e4d70666',
		'e1915f5cb1eca46c',
		'f325965ca16d629f',
		'575ff28e60381be5',
		'724506eb4c328a95'
	]
	
	pt.resize(0)
	for i in range(tv.size()):
		ec = NCrypt.hex_to_raw(tv[i])
		assert(_pba_equal(ec, SIPHASH.hash_raw(pt, ky, 2, 4, 8)))
		assert(_pba_equal(ec, NCrypt.hex_to_raw(SIPHASH.hash_hex(pt, ky, 2, 4, 8))))
		assert(_pba_equal(ec, Marshalls.base64_to_raw(SIPHASH.hash_base64(pt, ky, 2, 4, 8))))
	
		pt.append(i)
	
	# source: https://raw.githubusercontent.com/veorq/SipHash/master/vectors.h
	# SipHash-2-4 128-bit output
	tv = [
		'a3817f04ba25a8e66df67214c7550293',
		'da87c1d86b99af44347659119b22fc45',
		'8177228da4a45dc7fca38bdef60affe4',
		'9c70b60c5267a94e5f33b6b02985ed51',
		'f88164c12d9c8faf7d0f6e7c7bcd5579',
		'1368875980776f8854527a07690e9627',
		'14eeca338b208613485ea0308fd7a15e',
		'a1f1ebbed8dbc153c0b84aa61ff08239',
		'3b62a9ba6258f5610f83e264f31497b4',
		'264499060ad9baabc47f8b02bb6d71ed',
		'00110dc378146956c95447d3f3d0fbba',
		'0151c568386b6677a2b4dc6f81e5dc18',
		'd626b266905ef35882634df68532c125',
		'9869e247e9c08b10d029934fc4b952f7',
		'31fcefac66d7de9c7ec7485fe4494902',
		'5493e99933b0a8117e08ec0f97cfc3d9',
		'6ee2a4ca67b054bbfd3315bf85230577',
		'473d06e8738db89854c066c47ae47740',
		'a426e5e423bf4885294da481feaef723',
		'78017731cf65fab074d5208952512eb1',
		'9e25fc833f2290733e9344a5e83839eb',
		'568e495abe525a218a2214cd3e071d12',
		'4a29b54552d16b9a469c10528eff0aae',
		'c9d184ddd5a9f5e0cf8ce29a9abf691c',
		'2db479ae78bd50d8882a8a178a6132ad',
		'8ece5f042d5e447b5051b9eacb8d8f6f',
		'9c0b53b4b3c307e87eaee08678141f66',
		'abf248af69a6eae4bfd3eb2f129eeb94',
		'0664da1668574b88b935f3027358aef4',
		'aa4b9dc4bf337de90cd4fd3c467c6ab7',
		'ea5c7f471faf6bde2b1ad7d4686d2287',
		'2939b0183223fafc1723de4f52c43d35',
		'7c3956ca5eeafc3e363e9d556546eb68',
		'77c6077146f01c32b6b69d5f4ea9ffcf',
		'37a6986cb8847edf0925f0f1309b54de',
		'a705f0e69da9a8f907241a2e923c8cc8',
		'3dc47d1f29c448461e9e76ed904f6711',
		'0d62bf01e6fc0e1a0d3c4751c5d3692b',
		'8c03468bca7c669ee4fd5e084bbee7b5',
		'528a5bb93baf2c9c4473cce5d0d22bd9',
		'df6a301e95c95dad97ae0cc8c6913bd8',
		'801189902c857f39e73591285e70b6db',
		'e617346ac9c231bb3650ae34ccca0c5b',
		'27d93437efb721aa401821dcec5adf89',
		'89237d9ded9c5e78d8b1c9b166cc7342',
		'4a6d8091bf5e7d651189fa94a250b14c',
		'0e33f96055e7ae893ffc0e3dcf492902',
		'e61c432b720b19d18ec8d84bdc63151b',
		'f7e5aef549f782cf379055a608269b16',
		'438d030fd0b7a54fa837f2ad201a6403',
		'a590d3ee4fbf04e3247e0d27f286423f',
		'5fe2c1a172fe93c4b15cd37caef9f538',
		'2c97325cbd06b36eb2133dd08b3a017c',
		'92c814227a6bca949ff0659f002ad39e',
		'dce850110bd8328cfbd50841d6911d87',
		'67f14984c7da791248e32bb5922583da',
		'1938f2cf72d54ee97e94166fa91d2a36',
		'74481e9646ed49fe0f6224301604698e',
		'57fca5de98a9d6d8006438d0583d8a1d',
		'9fecde1cefdc1cbed4763674d9575359',
		'e3040c00eb28f15366ca73cbd872e740',
		'7697009a6a831dfecca91c5993670f7a',
		'5853542321f567a005d547a4f04759bd',
		'5150d1772f50834a503e069a973fbd7c'
	]

	pt.resize(0)
	for i in range(tv.size()):
		ec = NCrypt.hex_to_raw(tv[i])
		assert(_pba_equal(ec, SIPHASH.hash_raw(pt, ky, 2, 4, 16)))
		assert(_pba_equal(ec, NCrypt.hex_to_raw(SIPHASH.hash_hex(pt, ky, 2, 4, 16))))
		assert(_pba_equal(ec, Marshalls.base64_to_raw(SIPHASH.hash_base64(pt, ky, 2, 4, 16))))
		pt.append(i)
		
	return
		
# ==============================================================================

func test_prng() -> void:
	# test generation works
	for rl in [ 8, 12, 20 ]:
		var rng:CSPRNG = CSPRNG.new(rl)
		for i in range(1024): rng.rand_64()
	
	# test block generation
	for rl in [ 8, 12, 20 ]:
		var rng:CSPRNG = CSPRNG.new(rl)
		for i in [ 4, 8, 16, 32, 64, 128, 192, 256, 384, 512, 1024, 2069 ]:
			assert(rng.rand_raw(i).size() == i)
	
	return
	
	