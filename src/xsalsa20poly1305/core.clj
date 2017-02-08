(ns xsalsa20poly1305.core
  "Functions for XSalsa20Poly1305 encryption and decryption."
  (:import (java.security SecureRandom)
           (org.bouncycastle.crypto.engines XSalsa20Engine)
           (org.bouncycastle.crypto.macs Poly1305)
           (org.bouncycastle.crypto.params KeyParameter ParametersWithIV)
           (org.bouncycastle.util Arrays)))

(defn- nonce
  "Generate a random, 24-byte nonce."
  []
  (let [r (SecureRandom.)
        n (byte-array 24)]
    (.nextBytes r n)
    n))

(defn seal
  "Encrypts the given plaintext with the given key using XSalsa20Poly1305 and
  returns the ciphertext."
  [^bytes k ^bytes p]
  (let [n  (nonce)
        ce (XSalsa20Engine.)
        me (Poly1305.)
        sk (byte-array 32)
        o  (byte-array (+ (count p) 40))]

    ;; initialize xsalsa20
    (.init ce false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes ce sk 0 (count sk) sk 0)

    ;; encrypt plaintext
    (.processBytes ce p 0 (count p) o 40)

    ;; hash ciphertext
    (.init me (KeyParameter. sk))
    (.update me o 40 (count p))

    ;; prepend the mac
    (.doFinal me o 24)

    ;; prepend the nonce
    (System/arraycopy n 0 o 0 24)

    ;; return nonce + mac + ciphertext
    o))

(defn unseal
  [^bytes k ^bytes c]
  (let [n  (byte-array 24)
        ce (XSalsa20Engine.)
        me (Poly1305.)
        sk (byte-array 32)
        h1 (byte-array 16)
        h2 (byte-array 16)
        o  (byte-array (- (count c) 40))]

    ;; extract nonce
    (System/arraycopy c 0 n 0 24)

    ;; extract mac
    (System/arraycopy c 24 h1 0 16)

    (.init ce false (ParametersWithIV. (KeyParameter. k) n))

    ;; generate poly1305 subkey
    (.processBytes ce sk 0 (count sk) sk 0)

    ;; hash ciphertext
    (.init me (KeyParameter. sk))
    (.update me c 40 (count o))
    (.doFinal me h2 0)

    ;; check macs
    (when-not (Arrays/constantTimeAreEqual h1 h2)
      (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

    ;; decrypt plaintext
    (.processBytes ce c 40 (count o) o 0)

    ;; return plaintext
    o))
