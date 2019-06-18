# ==============================================================================
# NCryptBenchmark - benchmark suite for NCrypt
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
class_name NCryptBenchmark

# ==============================================================================
# CONSTANTS

const MAX_ITERS:int	= 10		# max number of iterations of a test
const MAX_TIME:int	= 30000		# max time to allow for a test (approx)

# ==============================================================================
# VARIABLES

# plaintext
var P:PoolByteArray

# keys and ivs, indexed by bit length
const A:Dictionary = { }

# ==============================================================================
# NCryptBenchmark

func _init() -> void:
	# generate key and iv buffers
	for i in [ 64, 128, 192, 256, 384, 512, 1024, 2048 ]:
		var ib:int = i>>3
		
		var a:PoolByteArray = PoolByteArray()
		a.resize(ib)
		for j in range(ib): a[j] = 0x80 if (j == 0) else 0x00
		
		A[i] = a
	
	# generate a 32k+ source plaintext
	# p0 is 512 ASCII bytes of Bacon Ipsum https://baconipsum.com
	var p0:PoolByteArray = 'Meatloaf turducken spare ribs, chuck aute lorem voluptate venison anim est excepteur pork aliquip hamburger. Tongue ribeye cillum anim sirloin pastrami bacon deserunt pork chop alcatra ground round sunt. Adipisicing in chuck bresaola id. Andouille proident turducken, pork chop labore chuck brisket shankle spare ribs capicola commodo voluptate rump in kielbasa. Ad tongue officia cupidatat, corned beef doner swine velit cupim. Shankle flank culpa short loin pig, pork belly pork chop. Pastrami aliqu deserunt. '.to_ascii()
	for i in range(32768/p0.size()):
		P.append_array(p0)
	assert(P.size() == 32768)
	return

func _print_results(a_title:String, a_results:Dictionary) -> void:
	print(a_title)
	for pl in a_results.keys():
		var avgms:float = a_results[pl]
		var avgrt:float = 1000.0 * (float(pl)/avgms)
		print('%5d time:%8.1fms rate:%9.1f bytes/sec' % [ pl, avgms, avgrt ])
	print(' ')
	return

# ==============================================================================

func run_all_tests() -> void:
	# run benchmarks
	test_aes_ecb()
	test_aes_cbc()
	test_aes_ctr()

	test_arcfour(0)
	test_arcfour(3072)

	test_chacha(8)
	test_chacha(12)
	test_chacha(20)

	test_sha256()
	test_hmac_sha256()
	test_siphash()
	
	test_prng_64()
	test_prng_block()
	return

# ==============================================================================
# BENCHMARKS

func test_aes_ecb() -> void:
	for kl in [ 128, 192, 256 ]:
		var results:Dictionary = {}
		
		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				AES.encrypt_ecb_raw(pt, A[kl])
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('AES-%d ECB:' % [ kl ], results)
	
	print(' ')
	return


func test_aes_cbc() -> void:
	for kl in [ 128, 192, 256 ]:
		var results:Dictionary = {}
		
		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				AES.encrypt_cbc_raw(pt, A[kl], A[128])
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
						
		_print_results('AES-%d CBC:' % [ kl ], results)
	
	print(' ')
	return
	

func test_aes_ctr() -> void:
	for kl in [ 128, 192, 256 ]:
		var results:Dictionary = {}
		
		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				AES.encrypt_ctr_raw(pt, A[kl], A[128])
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('AES-%d CTR:' % [ kl ], results)
	
	print(' ')
	return


func test_arcfour(a_drop:int) -> void:
	for kl in [ 256, 512, 1024, 2048 ]:
		var results:Dictionary = {}
				
		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				ARCFOUR.encrypt_raw(pt, A[kl], a_drop)
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('ARCFOUR-%d (drop %d):' % [ kl, a_drop ], results)
	
	print(' ')
	return
	
	
func test_chacha(a_rounds) -> void:
	for kl in [ 128, 256 ]:
		var results:Dictionary = {}

		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				CHACHA.encrypt_raw(pt, A[kl], A[64], 1, a_rounds)
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('CHACHA%d-%d:' % [ a_rounds, kl ], results)
	
	print(' ')
	return


func test_sha256() -> void:
	var results:Dictionary = {}
			
	for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
		var pt:PoolByteArray = P.subarray(0, pl-1)
		var st:int = OS.get_ticks_msec()
		var et:int = st
		var ic:int = 0
		while (true):
			SHA256.hash_raw(pt)
			et  = OS.get_ticks_msec()
			ic += 1
			if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
		
		results[pl] = float(et - st) / float(ic)
		
	_print_results('SHA256:', results)
	
	print(' ')
	return


func test_siphash() -> void:
	var results:Dictionary = {}
	
	for ol in [ 64, 128 ]:
		for cr in [ [2,4], [4,8] ]:
			var c:int = cr[0]
			var r:int = cr[1]
			for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
				var pt:PoolByteArray = P.subarray(0, pl-1)
				var st:int = OS.get_ticks_msec()
				var et:int = st
				var ic:int = 0
				while (true):
					SIPHASH.hash_raw(pt, A[128], c, r, ol>>3)
					et  = OS.get_ticks_msec()
					ic += 1
					if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
				
				results[pl] = float(et - st) / float(ic)
				
			_print_results('SIPHASH%d-%d (%d bit):' % [ c, r, ol ], results)
	
	print(' ')
	return
	
	
func test_hmac_sha256() -> void:
	for kl in [ 128, 512 ]:
		var results:Dictionary = {}

		for pl in [ 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768 ]:
			var pt:PoolByteArray = P.subarray(0, pl-1)
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				HMACSHA256.hmac_raw(pt, A[kl])
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('HMACSHA256 (%d bit key):' % kl, results)
	
	print(' ')
	return
	

func test_prng_64() -> void:
	print('CSPRNG-CHACHA (int64):')
	for rl in [ 8, 12, 20 ]:
		var rng:CSPRNG = CSPRNG.new(rl)
		var st:int = OS.get_ticks_msec()
		var et:int = st
		var ic:int = 0
		while (true):
			rng.rand_64()
			et  = OS.get_ticks_msec()
			ic += 1
			if ((et - st) > MAX_TIME): break
		
		var avgms:float = float(et - st) / float(ic)
		var avgrt:float = 1000.0 * (1.0/avgms)
		print(' r:%2d time:%8.1fms rate:%9.1f/sec' % [ rl, avgms, avgrt ])
	
	print(' ')
	return
	
		
func test_prng_block() -> void:
	for rl in [ 8, 12, 20 ]:
		var rng:CSPRNG = CSPRNG.new(rl)
		var results:Dictionary = {}
		
		for pl in [ 4, 8, 16, 32, 64, 128, 192, 256, 384, 512 ]:
			var st:int = OS.get_ticks_msec()
			var et:int = st
			var ic:int = 0
			while (true):
				rng.rand_raw(pl)
				et  = OS.get_ticks_msec()
				ic += 1
				if (ic >= MAX_ITERS || (et - st) > MAX_TIME): break
			
			results[pl] = float(et - st) / float(ic)
			
		_print_results('CSPRNG-CHACHA%d (block):' % rl, results)
	
	print(' ')
	return
