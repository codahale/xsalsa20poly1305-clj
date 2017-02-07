(ns xsalsa20poly1305.bench-test
  (:require [clojure.test :refer :all]
            [criterium.core :as c]
            [xsalsa20poly1305.core :refer :all]))

(def k (byte-array 32))

(defn- sep
  [n]
  (printf "\n\n######  %d bytes  ######\n" n))

(deftest ^:bench bench-all
  (doseq [n [100 1024 (* 10 1024) (* 100 1024)]]
    (sep n)
    (let [p (byte-array n)]
      (c/bench (seal k p)))))
