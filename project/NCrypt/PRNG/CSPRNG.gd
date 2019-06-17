# ==============================================================================
# CSPRNG - CSPRNG based on the FORTUNA construction and the CHACHA cipher
# https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
# https://en.wikipedia.org/wiki/Fortuna_(PRNG)
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
class_name CSPRNG

# ==============================================================================
# VARIABLES

var _cipher					= CHACHA._ChaChaBlockCipher.new()
var _rounds	: int			= 20
var _kstate	: PoolByteArray = PoolByteArray()
var _cstate	: PoolByteArray	= PoolByteArray()

# ==============================================================================
# CSPRNG

"""
Constructor.

Parameters
a_rounds:	Number of rounds to use in the internal CHACHA cipher used to generate random bits.
			Default 20. 8 or 12 can be used for increased speed at the expense of some security.
"""
func _init(a_rounds:int = 20) -> void:
	# initialise
	_rounds = a_rounds
	
	# initialise counter to 0
	_cstate.resize(16)
	for i in range(16): _cstate[i] = 0
		
	# initial seeding
	# seed with 2x state size = 768 bits
	var ent:PoolByteArray = PoolByteArray()
	ent.resize(96)
	for i in range(0, ent.size(), 4):
		var r:int = randi()
		ent[i  ] = (r >> 24) & 0xff
		ent[i+1] = (r >> 16) & 0xff
		ent[i+2] = (r >>  8) & 0xff
		ent[i+3] = (r      ) & 0xff
	add_entropy(ent)
	
	return
	
# increments the counter
func _inc_cstate() -> void:
	# 128-bit little endian increment
	for i in range(0,16):
		_cstate[i] = (_cstate[i] + 1) & 0xff
		if (_cstate[i] != 0): break
	return

# populates the _blk array with the encrypted counter value and increments the counter
func _gen_block() -> PoolByteArray:
	assert(_kstate.size() > 0)
	
	# get next 128 bits from chacha20 keystream
	var blk:PoolByteArray = _cipher.chacha20_block(_kstate, _cstate, 0, _rounds)
	blk.resize(16)
	
	# encrypt counter with keystream to create 128 bit fortuna block
	for i in range(16):	blk[i] ^= _cstate[i]

	# increment counter
	_inc_cstate()
	
	return blk

# ==============================================================================
# PUBLIC API

"""
Add entropy to the PRNG.

Parameters
a_ent	:	Entropy to add.
"""
func add_entropy(a_ent:PoolByteArray) -> void:
	# generate new key by securely combining with supplied entropy
	_kstate = SHA256.hash_raw(_kstate + a_ent)
	_inc_cstate()
	return


"""
Return a buffer filled with cryptographically secure random bytes.

Parameters
a_len	:	Desired size of buffer. Up to 1Mb.

Return	:	Initialised buffer.
"""
func rand_raw(a_len:int) -> PoolByteArray:
	assert(a_len > 0)
	assert(a_len < 0x100000)
	assert(_kstate.size() > 0)
	
	# append random bits to output buffer until it is large enough
	var op:PoolByteArray = PoolByteArray()
	while (op.size() < a_len):
		op.append_array(_gen_block())

	# generate two more blocks and concatenate as the next key
	_kstate = _gen_block() + _gen_block()
	
	# trim output buffer to correct size and return
	op.resize(a_len)
	return op
	

"""
Return a cryptographically secure random 64 bit integer.

Return	:	random 64 bit integer.
"""
func rand_64() -> int:
	var rb:PoolByteArray = rand_raw(8)
	
	var r:int = 0
	for i in range(8): r = (r << 8) | (rb[i] & 0xff)
	
	return r



	