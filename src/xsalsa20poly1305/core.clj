(ns xsalsa20poly1305.core
  "Functions for XSalsa20Poly1305 encryption and decryption."
  (:import (java.security SecureRandom)
           (org.bouncycastle.crypto.engines XSalsa20Engine)
           (org.bouncycastle.crypto.macs Poly1305)
           (org.bouncycastle.crypto.params KeyParameter ParametersWithIV)
           (org.bouncycastle.util Arrays)))

(def ^:private nonce-size 24)
(def ^:private mac-key-size 32)
(def ^:private mac-size 16)
(def ^:private overhead-size (+ mac-size nonce-size))

(defn- nonce
  "Generate a random, 24-byte nonce."
  []
  (let [r (SecureRandom.)
        n (byte-array nonce-size)]
    (.nextBytes r n)
    n))

(defn seal
  "Encrypts the given plaintext with the given key using XSalsa20Poly1305 and
  returns the ciphertext."
  [^bytes k ^bytes p]
  (let [xsalsa20 (XSalsa20Engine.)
        poly1305 (Poly1305.)
        n        (nonce)
        sk       (byte-array mac-key-size)
        o        (byte-array (+ (count p) overhead-size))]

    ;; initialize xsalsa20
    (.init xsalsa20 false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes xsalsa20 sk 0 mac-key-size sk 0)

    ;; encrypt plaintext
    (.processBytes xsalsa20 p 0 (count p) o overhead-size)

    ;; hash ciphertext
    (.init poly1305 (KeyParameter. sk))
    (.update poly1305 o overhead-size (count p))

    ;; prepend the mac
    (.doFinal poly1305 o nonce-size)

    ;; prepend the nonce
    (System/arraycopy n 0 o 0 nonce-size)

    ;; return nonce + mac + ciphertext
    o))

(defn unseal
  "Decrypts the given ciphertext with the given key using XSalsa20Poly1305 and
  returns the plaintext. If the ciphertext has been modified in any way, or if
  the key is incorrect, an IllegalArgumentException is thrown."
  [^bytes k ^bytes c]
  (when-not (< overhead-size (count c))
    ;; check for correct size
    (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

  (let [xsalsa20 (XSalsa20Engine.)
        poly1305 (Poly1305.)
        n        (byte-array nonce-size)
        sk       (byte-array mac-key-size)
        h1       (byte-array mac-size)
        h2       (byte-array mac-size)
        o        (byte-array (- (count c) overhead-size))]

    ;; extract nonce
    (System/arraycopy c 0 n 0 nonce-size)

    ;; extract mac
    (System/arraycopy c nonce-size h1 0 mac-size)

    ;; initialize xsalsa20
    (.init xsalsa20 false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes xsalsa20 sk 0 mac-key-size sk 0)

    ;; hash ciphertext
    (.init poly1305 (KeyParameter. sk))
    (.update poly1305 c overhead-size (count o))
    (.doFinal poly1305 h2 0)

    ;; check macs
    (when-not (Arrays/constantTimeAreEqual h1 h2)
      (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

    ;; decrypt plaintext
    (.processBytes xsalsa20 c overhead-size (count o) o 0)

    ;; return plaintext
    o))
