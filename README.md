# NCrypt

**Cryptographic Primitives in pure GDScript for [Godot Engine](https://godotengine.org/)**

This project contains pure GDScript implementations of a number of cryptographic primitives:

* **CIPHERS**
  * [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard): 128/192/256 bit keys; ECB, CBC, CTR modes
  * [ARCFOUR](https://en.wikipedia.org/wiki/RC4): 8-2048 bit keys; supports dropping initial keystream bytes
  * [CHACHA](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant): 128/256 bit keys; 64/96 bit nonce; 8/12/20 rounds
* **PADDING**
  * [PKCS#5](https://en.wikipedia.org/wiki/PKCS)
* **HASH**
  * [SHA256](https://en.wikipedia.org/wiki/SHA-2)
  * [HMAC-SHA256](https://en.wikipedia.org/wiki/HMAC)
  * [SIPHASH](https://en.wikipedia.org/wiki/SipHash): configurable rounds; 64/128 bit hash
* **CSPRNG**
  * [CSRPNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) based on the [FORTUNA](https://en.wikipedia.org/wiki/Fortuna_(PRNG)) construction and CHACHA8/12/20 ciphers
  
  
These implementations are interoperable with common implementation of the same algorithms.

A test and benchmark suite are included.

Contributions of improvements and/or further primitives are welcome.


## MOTIVATION

Godot Engine provides only limited cryptography support in the core engine. Back-end services
commonly used in contemporary games often require encryption or digital signatures in their
protocols, and, from a developer perspective, adding these features via GDScript is the most
straightforward approach (at the cost of performance).

It should be noted that it is possible to add these features to Godot Engine through other
means that may be more suitable for a particular project, namely via C# scripting, GDNative
plugins, or extending the core engine.

I needed a HMAC-SHA256, so I implemented SHA256 and HMAC, then got a little carried away...


## USAGE

Godot Engine 3.1 is required.

Copy the _NCrypt_ folder, or just the classes you require, into your Godot Engine project.
The classes are now available for use in your scripts.

The public methods of each class are documented inline in the code.

Typical use involves invoking a static method with `PoolByteArray` parameters containing
plaintext, key, initialisation vector etc., and obtaining either a raw `PoolByteArray` or
a hexadecimal or Base64 encoded `String` as a result.

Each primitive has specific requirements for its parameters. Please refer to the inline
documentation for details.

`String` objects may be converted to `PoolByteArray` objects for parameters using
the built-in `.to_ascii()` or `.to_utf8()` methods.

Implementing cryptography is extremely easy to get wrong and leave your systems and secrets
exposed. Research the algorithms, their parameters, usage guidance and existing attacks on
them to help you decide what best to use for your situation.

If you need a specific algorithm implemented, or general help and/or guidance around
implementing cryptography in your project, consider hiring me.


## EXAMPLES

Get the SHA256 of a `PoolByteArray` as a `PoolByteArray`:

```
var hash:PoolByteArray = SHA256.hash_buf(buffer)
```


Get the SHA256 of a `String` as a `PoolByteArray`:

```
var hash:PoolByteArray = SHA256.hash_buf('Bacon ipsum dolor'.to_ascii())
```


Get a Base64 HMAC-SHA256 of a `String` with the secret key "porkchop99" in a `String`:

```
var hmac:String = HMACSHA256.hmac_b64('Bacon ipsum dolor'.to_ascii(), 'porkchop99'.to_ascii())
```


Encrypt a `String` with CHACHA, using 20 rounds (default) and a 128-bit key, and encode
the result as hexadecimal.
`iv` should be an 8 or 12 byte `PoolByteArray` filled with unique secure random values.

```
var plain:PoolByteArray = 'Bacon ipsum dolor'.to_ascii()
var key:PoolByteArray   = 'porkchopporkchop'.to_ascii()
var cipherHex:String    = CHACHA.encrypt_hex(plain, key, iv)
```


Encrypt a `String` with AES-256 in CBC mode and encode as Base64.
Note the use of PKCS#5 to pad the input buffer to the length requirements of AES.
The secret key in this example is 32 zero bytes.
`iv` should be 16 byte `PoolByteArray` filled with unique secure random values.

```
var plain:PoolByteArray = PKCS5.pad('Bacon ipsum dolor'.to_ascii(), 16)
var key:PoolByteArray   = PoolByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
var cipherB64:String    = AES.encrypt_cbc_b64(plain, key, iv)
```


Decrypt the above Base64 `String`.
The `key` and `iv` parameters must, of course, be the same as those used for encryption.

```
var plain:String = PKCS5.unpad(AES.decrypt_cbc_b64(cipherB64, key, iv).to_ascii())
```


## PERFORMANCE

__SLOW!__

Some indicative benchmark results are included in the _benchmark_ folder.

On a typical mobile ARM7 processor you can expect AES-128 to encrypt at around 6Kb / second.
ARCFOUR and CHACHA are faster, but can still take several seconds to process a multi-kilobyte buffer.

Bear this in mind when integrating NCrypt into your project. You can easily freeze the
main thread for a number of frames even when dealing with small buffers. If possible, perform
encryption/decryption operations at non-critical times and on background threads.


## RUNNING THE TEST SUITES

Open a terminal and change working directory to the `project` directory.

Execute the required test runner script from the command line with the Godot Engine binary.

__Run the unit tests:__

`/path/to/godot --path /path/to/project -s ./NCryptTest/NCryptTestRunner.gd`

__Run the benchmark tests:__

`/path/to/godot --path /path/to/project -s ./NCryptTest/NCryptBenchmarkRunner.gd`



## POSSIBLE ADDITIONS

* Streaming interfaces for hashes and ciphers
* Further algorithms. For example: XXTEA, SHA-1, MD5, ISAAC
* Further examples

Contributions are welcome.

Public Key, GCM and POLY1305 primitives are likely to be difficult to implement in GDScript.
If you need these, using one of the alternative approaches is recommended.

Note that no effort has been made to secure the implementations against memory snooping,
timing, side channel or other attacks. If you need these, using one of the alternative approaches
is recommended.

Future versions of Godot Engine may incorporate more cryptographic functions into the core engine, 
potentially making this project obsolete. We can hope.


## LICENSE

MIT License

Copyright (c) 2019 John Girvin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
