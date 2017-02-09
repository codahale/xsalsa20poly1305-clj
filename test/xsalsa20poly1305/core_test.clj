(ns xsalsa20poly1305.core-test
  (:require [buddy.core.codecs :as codecs]
            [clojure.test :refer :all]
            [xsalsa20poly1305.core :refer :all :as xsalsa20poly1305]))

(def n (codecs/str->bytes "iliveonaayellowsubmarine"))

(def k (codecs/str->bytes "ayellowsubmarineayellowsubmarine"))

(def p (codecs/str->bytes "this is a test"))

(def c (codecs/hex->bytes "6f2ebaec4c32318b511c4f458f54f700322bc9abe1289ae0ea0fac16978d"))

(deftest generate-nonce-test
  (is (= 24 (count (generate-nonce)))))

(deftest seal-test
  (is (= (codecs/bytes->hex c) (codecs/bytes->hex (seal k n p)))))

(deftest unseal-test
  (is (= (codecs/bytes->hex p) (codecs/bytes->hex (unseal k n c)))))

(deftest short-key-test
  (is (thrown? IllegalArgumentException (seal (byte-array 10) n p))))

(deftest short-nonce-test
  (is (thrown? IllegalArgumentException (seal k (byte-array 10) p))))

(deftest short-message-test
  (is (thrown? IllegalArgumentException (unseal k n (byte-array 12)))))

(deftest tampering-test
  (let [^bytes c2 (into-array Byte/TYPE c)]
    ;; twiddle a single bit
    (aset c2 18 (byte (bit-xor (aget c2 18) 1)))
    (is (thrown? IllegalArgumentException (unseal k n c2)))))

(deftest wrong-key-test
  (let [^bytes k2 (into-array Byte/TYPE k)]
    ;; twiddle a single bit
    (aset k2 5 (byte (bit-xor (aget k2 5) 1)))
    (is (thrown? IllegalArgumentException (unseal k2 n c)))))

(deftest wrong-nonce-test
  (let [^bytes n2 (into-array Byte/TYPE n)]
    ;; twiddle a single bit
    (aset n2 5 (byte (bit-xor (aget n2 5) 1)))
    (is (thrown? IllegalArgumentException (unseal k n2 c)))))
