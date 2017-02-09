(ns xsalsa20poly1305.core
  "Functions for XSalsa20Poly1305 encryption and decryption."
  (:import (java.security MessageDigest SecureRandom)
           (org.bouncycastle.crypto.engines XSalsa20Engine)
           (org.bouncycastle.crypto.macs Poly1305)
           (org.bouncycastle.crypto.params KeyParameter ParametersWithIV)))

(def ^:private nonce-size 24)
(def ^:private mac-key-size 32)
(def ^:private mac-size 16)

(defn generate-nonce
  "Generates a random, 24-byte nonce."
  []
  (let [r (SecureRandom.) ; getInstanceStrong pulls from /dev/random
        n (byte-array nonce-size)]
    (.nextBytes r n)
    n))

(defn seal
  "Encrypts the given plaintext with the given key and nonce, returning the
  ciphertext. The key must be 32 bytes long and the nonce must be 24 bytes long.

  If the nonce is not provided, one is generated and prepended to the
  ciphertext."
  ([^bytes k ^bytes p]
   (let [n (generate-nonce)
         c (seal k n p)
         o (byte-array (+ (count c) nonce-size))]
     (System/arraycopy n 0 o 0 nonce-size)
     (System/arraycopy c 0 o nonce-size (count c))
     o))

  ([^bytes k ^bytes n ^bytes p]
   (let [xsalsa20 (XSalsa20Engine.)
         poly1305 (Poly1305.)
         sk       (byte-array mac-key-size)
         o        (byte-array (+ (count p) mac-size))]

     ;; initialize xsalsa20
     (.init xsalsa20 false (ParametersWithIV. (KeyParameter. k) n))

     ;; generate poly1305 subkey
     (.processBytes xsalsa20 sk 0 mac-key-size sk 0)

     ;; encrypt plaintext
     (.processBytes xsalsa20 p 0 (count p) o mac-size)

     ;; hash ciphertext
     (.init poly1305 (KeyParameter. sk))
     (.update poly1305 o mac-size (count p))

     ;; prepend the mac
     (.doFinal poly1305 o 0)

     ;; return mac + ciphertext
     o)))

(defn unseal
  "Decrypts the given ciphertext with the given key and nonce, returning the
  plaintext. If the ciphertext has been modified in any way, or if the key or
  nonce is incorrect, an IllegalArgumentException is thrown.

  If the nonce is not provided, it is assumed to be the first 24 bytes of the
  ciphertext."
  ([^bytes k ^bytes c]
   (when-not (< nonce-size (count c))
     (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

   (let [n (byte-array nonce-size)
         b (byte-array (- (count c) nonce-size))]
     (System/arraycopy c 0 n 0 nonce-size)
     (System/arraycopy c nonce-size b 0 (count b))
     (unseal k n b)))

  ([^bytes k ^bytes n ^bytes c]
   ;; check size
   (when-not (< mac-size (count c))
     (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

   (let [xsalsa20 (XSalsa20Engine.)
         poly1305 (Poly1305.)
         sk       (byte-array mac-key-size)
         h1       (byte-array mac-size)
         h2       (byte-array mac-size)
         o        (byte-array (- (count c) mac-size))]

     ;; initialize xsalsa20
     (.init xsalsa20 false (ParametersWithIV. (KeyParameter. k) n))

     ;; generate poly1305 subkey
     (.processBytes xsalsa20 sk 0 mac-key-size sk 0)

     ;; hash ciphertext
     (.init poly1305 (KeyParameter. sk))
     (.update poly1305 c mac-size (count o))

     ;; calculate the mac
     (.doFinal poly1305 h1 0)

     ;; extract mac
     (System/arraycopy c 0 h2 0 mac-size)

     ;; check macs
     (when-not (MessageDigest/isEqual h1 h2)
       (throw (IllegalArgumentException. "Unable to decrypt ciphertext")))

     ;; decrypt plaintext
     (.processBytes xsalsa20 c mac-size (count o) o 0)

     ;; return plaintext
     o)))
