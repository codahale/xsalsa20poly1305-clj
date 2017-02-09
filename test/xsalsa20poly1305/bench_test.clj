(ns xsalsa20poly1305.bench-test
  (:require [clojure.test :refer :all]
            [criterium.core :as c]
            [xsalsa20poly1305.core :refer :all]))

(def n (byte-array 24))
(def k (byte-array 32))

(defn- sep
  [n]
  (printf "\n\n######  %d bytes  ######\n" n))

(deftest ^:bench bench-all
  (doseq [i [100 1024 (* 10 1024) (* 100 1024)]]
    (sep i)
    (let [p (byte-array i)]
      (c/bench (seal k n p)))))
