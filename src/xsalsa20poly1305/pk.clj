(ns xsalsa20poly1305.pk
  (:import (java.security SecureRandom)
           (org.bouncycastle.asn1.x9 X9ECParameters)
           (org.bouncycastle.crypto.ec CustomNamedCurves)
           (org.bouncycastle.crypto.engines Salsa20Engine)
           (org.bouncycastle.math.ec.custom.djb Curve25519FieldElement
                                                Curve25519Point)
           (org.bouncycastle.util Pack)))

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


(defn shared-secret
  [^bytes k ^bytes p]
  (let [base (.getX (.multiply g (BigInteger. k)))
        other (Curve25519FieldElement. (BigInteger. p))
        shared (.toByteArray (.toBigInteger (.multiply base other)))]
    ;; FIXME need HSalsa20 implementation to process shared point
    shared
    ))

(comment
  (let [[k1 p1] (generate-key-pair)
        [k2 p2] (generate-key-pair)]
    (prn (buddy.core.codecs/bytes->hex (shared-secret k1 p2)))
    (prn (buddy.core.codecs/bytes->hex (shared-secret k2 p1))))


  )
