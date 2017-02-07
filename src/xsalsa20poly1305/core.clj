(ns xsalsa20poly1305.core
  "Functions for XSalsa20Poly1305 encryption and decryption."
  (:import (java.security SecureRandom)
           (com.github.nitram509.jmacaroons.crypto.neilalexander.jnacl xsalsa20poly1305)))

(def ^:private nonce-size 24)
(def ^:private box-size 32)
(def ^:private msg-size 16)

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
  [^bytes k ^bytes plaintext]
  (let [m (byte-array (+ (count plaintext) box-size))
        n (nonce)
        c (byte-array (count m))
        o (byte-array (+ (count plaintext) msg-size (count n)))]

    ;; copy the data into the input buffer
    (System/arraycopy plaintext 0 m box-size (count plaintext))

    ;; encrypt the data
    (when (neg? (xsalsa20poly1305/crypto_secretbox c m (count m) n k))
      (throw (IllegalArgumentException. "Unable to encrypt data")))

    ;; copy the nonce into the output buffer
    (System/arraycopy n 0 o 0 (count n))

    ;; copy the ciphertext into the output buffer
    (System/arraycopy c msg-size o (count n) (- (count c) msg-size))

    ;; return the nonce with the ciphertext appended
    o))

(defn unseal
  "Decrypts the given ciphertext with the given key using XSalsa20Poly1305 and
  returns the plaintext."
  [^bytes k ^bytes ciphertext]
  (let [n (byte-array nonce-size)
        c (byte-array (- (+ (count ciphertext) msg-size) (count n)))
        m (byte-array (count c))
        o (byte-array (- (count c) box-size))]

    ;; copy the nonce
    (System/arraycopy ciphertext 0 n 0 (count n))

    ;; copy the ciphertext
    (System/arraycopy ciphertext (count n) c msg-size (- (count ciphertext)
                                                         (count n)))

    (when (neg? (xsalsa20poly1305/crypto_secretbox_open m c (count c) n k))
      (throw (IllegalArgumentException. "Unable to decrypt data")))

    ;; copy the plaintext
    (System/arraycopy m box-size o 0 (- (count m) box-size))

    ;; return the plaintext
    o))
