(ns xsalsa20poly1305.bench-test
  (:require [caesium.crypto.secretbox :as secretbox]
            [clojure.test :refer :all]
            [criterium.core :as c]
            [xsalsa20poly1305.core :as xsalsa20poly1305]
            [xsalsa20poly1305.simplebox :as simplebox]))

(def n (byte-array 24))
(def k (byte-array 32))

(defn- sep
  [s n]
  (printf "\n\n######  %s/%d bytes  ######\n" s n))

(deftest ^:bench bench-core
  (doseq [i [100 1024 (* 10 1024)]]
    (sep "core" i)
    (let [p (byte-array i)]
      (c/bench (xsalsa20poly1305/seal k n p)))))

(deftest ^:bench bench-caesium
  (doseq [i [100 1024 (* 10 1024)]]
    (sep "caesium" i)
    (let [p (byte-array i)]
      (c/bench (secretbox/encrypt k n p)))))

(deftest ^:bench bench-simplebox
  (doseq [i [100 1024 (* 10 1024)]]
    (sep "simplebox" i)
    (let [p (byte-array i)]
      (c/bench (simplebox/seal k p)))))
