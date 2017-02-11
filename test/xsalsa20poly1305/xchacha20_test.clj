(ns xsalsa20poly1305.xchacha20-test
  (:require [buddy.core.codecs :as codecs]
            [clojure.test :refer :all]
            [xsalsa20poly1305.xchacha20 :refer :all]))

(def n (codecs/str->bytes "iliveonaayellowsubmarine"))

(def k (codecs/str->bytes "ayellowsubmarineayellowsubmarine"))

(def p (codecs/str->bytes "this is a test"))

(deftest roundtrip-test
  (is (= (codecs/bytes->hex p)
         (codecs/bytes->hex (unseal k n (seal k n p))))))
