(ns xsalsa20poly1305.simplebox
  "Convenience functions for encryption without requiring nonce management.

  Compatible with RbNaCl's Simplebox construction, but generates
  misuse-resistant nonces."
  (:require [xsalsa20poly1305.core :refer [nonce-size] :as xsalsa20poly1305]))

(defn seal
  "Encrypts the given plaintext with the given key, returning the ciphertext.
  The key must be 32 bytes long."
  ^bytes [^bytes k ^bytes p]
  (let [n (xsalsa20poly1305/generate-nmr-nonce k p)
        c (xsalsa20poly1305/seal k n p)
        o (byte-array (+ (count c) nonce-size))]
    (System/arraycopy n 0 o 0 nonce-size)
    (System/arraycopy c 0 o nonce-size (count c))
    o))

(defn unseal
  "Decrypts the given ciphertext with the given key, returning the plaintext. If
  the ciphertext has been modified in any way, or if the key is incorrect,
  throws an IllegalArgumentException."
  ^bytes [^bytes k ^bytes c]
  (let [n (byte-array nonce-size)
        b (byte-array (max 0 (- (count c) nonce-size)))]
    (System/arraycopy c 0 n 0 (min (count c) nonce-size))
    (System/arraycopy c (min (count c) nonce-size) b 0 (count b))
    (xsalsa20poly1305/unseal k n b)))
