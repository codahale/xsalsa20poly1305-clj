(ns xsalsa20poly1305.bench-test
  (:require [caesium.crypto.secretbox :as secretbox]
            [caesium.magicnonce.secretbox :as magicnonce]
            [clojure.test :refer :all]
            [criterium.core :as c]
            [xsalsa20poly1305.core :as xsalsa20poly1305]
            [xsalsa20poly1305.simplebox :as simplebox]))

(def n (byte-array 24))
(def k (byte-array 32))

(defn- sep
  [s n]
  (printf "\n\n######  %s/%d bytes  ######\n" s n))

(def sizes [100 1024 (* 10 1024)])

(deftest ^:bench bench-core
  (doseq [i sizes]
    (sep "core/seal" i)
    (let [p (byte-array i)]
      (c/bench (xsalsa20poly1305/seal k n p)))))

(deftest ^:bench bench-caesium
  (doseq [i sizes]
    (sep "caesium/secretbox/encrypt" i)
    (let [p (byte-array i)]
      (c/bench (secretbox/encrypt k n p)))))

(deftest ^:bench bench-caesium-nmr
  (doseq [i sizes]
    (sep "caesium/magicnonce/secretbox-nmr" i)
    (let [p (byte-array i)]
      (c/bench (magicnonce/secretbox-nmr p k)))))

(deftest ^:bench bench-simplebox
  (doseq [i sizes]
    (sep "simplebox/seal" i)
    (let [p (byte-array i)]
      (c/bench (simplebox/seal k p)))))
