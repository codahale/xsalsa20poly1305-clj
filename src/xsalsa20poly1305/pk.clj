(ns xsalsa20poly1305.pk
  (:import (java.security SecureRandom)
           (org.bouncycastle.asn1.x9 X9ECParameters)
           (org.bouncycastle.crypto.ec CustomNamedCurves)
           (org.bouncycastle.crypto.engines Salsa20Engine)
           (org.bouncycastle.math.ec.custom.djb Curve25519FieldElement
                                                Curve25519Point)
           (org.bouncycastle.util Pack)
           (xsalsa20poly1305.internal hsalsa20)))

(def ^:private ^X9ECParameters curve25519
  (CustomNamedCurves/getByName "Curve25519"))

(def ^:private ^Curve25519Point g
  (.getG curve25519))

(defn generate-key-pair
  []
  (let [r (SecureRandom.)
        k (byte-array 32)]
    (.nextBytes r k)
    [k (.toByteArray (.toBigInteger (.getX (.multiply g (BigInteger. k)))))]))

(def ^:private zeros (byte-array 32))

(def ^:private sigma (.getBytes "expand 32-byte k"))

(defn shared-secret
  [^bytes k ^bytes p]
  (let [base (.getX (.multiply g (BigInteger. k)))
        other (Curve25519FieldElement. (BigInteger. p))
        shared (.toByteArray (.toBigInteger (.multiply base other)))]
    (hsalsa20/crypto_core shared zeros shared sigma)
    shared))

(comment
  (let [[k1 p1] (generate-key-pair)
        [k2 p2] (generate-key-pair)
        n       (xsalsa20poly1305.core/generate-nonce)
        p       (buddy.core.codecs/str->bytes "this is an example")]
    (prn :sh1 (buddy.core.codecs/bytes->hex (shared-secret k1 p2)))
    (prn :sh2 (buddy.core.codecs/bytes->hex (shared-secret k2 p1)))


    (let [kp (caesium.crypto.box/keypair!)
          k3 (.array (:secret kp))
          p3 (.array (:public kp))]
      (let [c (caesium.crypto.box/box-easy p n p2 k3)]
        (prn (buddy.core.codecs/bytes->hex c))
        (let [s (shared-secret k2 p3)]
          (xsalsa20poly1305.core/unseal s n c)
          )
        )
      ))


  )
