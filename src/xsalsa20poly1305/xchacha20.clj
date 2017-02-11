(ns xsalsa20poly1305.xchacha20
  (:import (java.security MessageDigest)
           (org.bouncycastle.crypto.macs Poly1305)
           (org.bouncycastle.crypto.params KeyParameter ParametersWithIV)
           (org.bouncycastle.util Pack)
           (xsalsa20poly1305 XChaCha20Engine)))

(def ^:private mac-key-size 32)
(def ^:private mac-size 16)

(defn seal
  "Encrypts the given plaintext with the given key and nonce, returning the
  ciphertext. The key must be 32 bytes long and the nonce must be 24 bytes long.

  N.B.: The nonce *must* be unique across all messages encrypted with a given
  key. If a nonce is used twice with the same key, the confidentiality and
  integrity of messages encrypted with that key will be compromised. Either use
  `generate-nonce`, which securely generates random nonces, or another
  arrangement which will avoid duplicate nonces. Alternatively, use the
  `simplebox/*` functions, which do all the nonce management for you."
  [^bytes k ^bytes n ^bytes p]
  (let [xchacha20 (XChaCha20Engine.)
        poly1305  (Poly1305.)
        sk        (byte-array mac-key-size)
        o         (byte-array (+ (count p) mac-size))]

    ;; initialize xsalsa20
    (.init xchacha20 false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes xchacha20 sk 0 mac-key-size sk 0)

    ;; encrypt plaintext
    (.processBytes xchacha20 p 0 (count p) o mac-size)

    ;; hash ciphertext
    (.init poly1305 (KeyParameter. sk))
    (.update poly1305 o mac-size (count p))

    ;; prepend the mac
    (.doFinal poly1305 o 0)

    ;; return mac + ciphertext
    o))

(defn unseal
  "Decrypts the given ciphertext with the given key and nonce, returning the
  plaintext. If the ciphertext has been modified in any way, or if the key or
  nonce is incorrect, throws an IllegalArgumentException."
  [^bytes k ^bytes n ^bytes c]
  (let [xchacha20 (XChaCha20Engine.)
        poly1305  (Poly1305.)
        sk        (byte-array mac-key-size)
        h1        (byte-array mac-size)
        h2        (byte-array mac-size)
        o         (byte-array (max 0 (- (count c) mac-size)))]

    ;; initialize xsalsa20
    (.init xchacha20 false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes xchacha20 sk 0 mac-key-size sk 0)

    ;; hash ciphertext
    (.init poly1305 (KeyParameter. sk))
    (.update poly1305 c mac-size (count o))

    ;; calculate the mac
    (.doFinal poly1305 h1 0)

    ;; extract mac
    (System/arraycopy c 0 h2 0 (min (count c) mac-size))

    ;; check macs
    (when-not (MessageDigest/isEqual h1 h2)
      (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

    ;; decrypt plaintext
    (.processBytes xchacha20 c mac-size (count o) o 0)

    ;; return plaintext
    o))
