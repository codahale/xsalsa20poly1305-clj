# xsalsa20poly1305

A Clojure implementation of XSalsa20Poly1305 authenticated encryption,
compatible with DJB's NaCl `secretbox` construction. Includes a set of functions
compatible with RbNaCl's SimpleBox construction, which automatically manages
nonces for you in a misuse-resistant fashion.

For small messages, it's about as fast as `libsodium`-based libraries like
Caesium and Kalium, but depends only on Bouncy Castle, which is pure Java.

## Usage

```clojure
(require '[xsalsa20poly1305.core :as xsalsa20poly1305])

(def k (.getBytes "ayellowsubmarineayellowsubmarine"))

(def n (xsalsa20poly1305/generate-nonce))

(def p (.getBytes "this is a test"))

(def c (xsalsa20poly1305/seal k n p))

(prn (xsalsa20poly1305/unseal k n c))

;; or, if you don't want to manage the nonces yourself

(require '[xsalsa20poly1305.simplebox :as simplebox])

(def c2 (simplebox/seal k p))

(prn (simplebox/unreal k c2))
```

## Misuse-Resistant Nonces

XSalsa20Poly1305 is composed of two cryptographic primitives: XSalsa20, a stream
cipher, and Poly1305, a message authentication code. In order to be secure, both
require a _nonce_ -- a bit string which can only be used once for any given key.
If a nonce is re-used -- i.e., used to encrypt two different messages -- this
can have catastrophic consequences for the confidentiality and integrity of the
encrypted messages: an attacker may be able to recover plaintext messages and
even forge seemingly-valid messages. As a result, it is incredibly important
that nonces be unique.

XSalsa20 uses 24-byte (192-bit) nonces, which makes the possibility of a secure
random number generator generating the same nonce twice essentially impossible,
even over trillions of messages. For normal operations, `core/generate-nonce`
(which simply returns 24 bytes from `SecureRandom`) should be safe to use. But
because of the downside risk of nonce misuse, this library provides a secondary
function for generating misuse-resistant nonces: `core/generate-nmr-nonce`,
which requires the key and message the nonce will be used to encrypt.

`generate-nmr-nonce` uses the BLAKE2b hash algorithm, keyed with the given key
and using randomly-generated 128-bit salt and personalization parameters. If the
local `SecureRandom` implementation is functional, the hash algorithm mixes
those 256 bits of entropy along with the key and message to produce a 192-bit
nonce, which will have the same chance of collision as `generate-nonce`. In the
event that the local `SecureRandom` implementation is misconfigured, exhausted
of entropy, or otherwise compromised, the generated nonce will be unique to the
given combination of key and message, thereby preserving the security of the
messages. Please note that in this event, using `generate-nmr-nonce` to encrypt
messages will be deterministic -- duplicate messages will produce duplicate
ciphertexts, and this will be observable to any attackers.

Because of the catastrophic downside risk of nonce reuse, the `simplebox`
functions use `generate-nmr-nonce` to generate nonces.

## License

Copyright © 2017 Coda Hale

Distributed under the Eclipse Public License either version 1.0 or (at your
option) any later version.
