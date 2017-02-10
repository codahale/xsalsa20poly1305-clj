# xsalsa20poly1305

A Clojure implementation of XSalsa20Poly1305 authenticated encryption,
compatible with DJB's NaCl. Includes a set of functions compatible with RbNaCl's
SimpleBox construction, which automatically manages nonces for you.

## Usage

```clojure
(require '[xsalsa20poly1305.core :as xsalsa20poly1305])

(def k (.getBytes "ayellowsubmarineayellowsubmarine"))

(def n (xsalsa20poly1305/generate-nonce))

(def p (.getBytes "this is a test"))

(def c (xsalsa20poly1305/seal k n p))

(prn (xsalsa20poly1305/unseal k n c))

;; or, if you don't want to manage the nonces yourself

(require '[xsalsa20poly1305.simplebox :as simplebox])

(def c2 (simplebox/seal k p))

(prn (simplebox/unreal k c2))
```

## License

Copyright © 2017 Coda Hale

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
