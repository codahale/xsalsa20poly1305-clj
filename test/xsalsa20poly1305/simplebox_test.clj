(ns xsalsa20poly1305.simplebox-test
  (:require [buddy.core.codecs :as codecs]
            [clojure.test :refer :all]
            [xsalsa20poly1305.simplebox :refer :all]))

(def k (codecs/str->bytes "ayellowsubmarineayellowsubmarine"))

(def p (codecs/str->bytes "this is a test"))

(deftest roundtrip-test
  (is (= (codecs/bytes->hex p) (codecs/bytes->hex (unseal k (seal k p))))))

(deftest short-message-test
  (is (thrown? IllegalArgumentException (unseal k (byte-array 22)))))
