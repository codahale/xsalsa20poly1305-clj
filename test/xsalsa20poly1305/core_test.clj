(ns xsalsa20poly1305.core-test
  (:require [buddy.core.codecs :as codecs]
            [clojure.test :refer :all]
            [mocko.core :refer :all]
            [xsalsa20poly1305.core :refer :all :as xsalsa]))

(def k (codecs/str->bytes "ayellowsubmarineayellowsubmarine"))

(def p (codecs/str->bytes "this is a test"))

(def c (codecs/hex->bytes (str "696c6976656f6e616179656c6c6f777375626d6172696e"
                               "656f2ebaec4c32318b511c4f458f54f700322bc9abe128"
                               "9ae0ea0fac16978d")))

(deftest seal-test
  (with-mocks
    (mock! #'xsalsa/nonce {[] (codecs/str->bytes "iliveonaayellowsubmarine")})
    (is (= (codecs/bytes->hex c) (codecs/bytes->hex (seal k p))))))

(deftest unseal-test
  (is (= (codecs/bytes->hex p) (codecs/bytes->hex (unseal k c)))))

(deftest short-key-test
  (is (thrown? IllegalArgumentException (seal (byte-array 10) p))))

(deftest short-message-test
  (is (thrown? IllegalArgumentException (unseal k (byte-array 20)))))

(deftest tampering-test
  (let [^bytes c2 (into-array Byte/TYPE c)]
    ;; twiddle a single bit
    (aset c2 36 (byte (bit-xor (aget c2 36) 1)))
    (is (thrown? IllegalArgumentException (unseal k c2)))))

(deftest wrong-key-test
  (let [^bytes k2 (into-array Byte/TYPE k)]
    ;; twiddle a single bit
    (aset k2 5 (byte (bit-xor (aget k2 5) 1)))
    (is (thrown? IllegalArgumentException (unseal k2 c)))))
