# xsalsa20poly1305

A Clojure implementation of XSalsa20Poly1305 authenticated encryption,
compatible with DJB's NaCl.

## Usage

```clojure
(require '[xsalsa20poly1305.core :as xsalsa20poly1305])

(def k (.getBytes "ayellowsubmarineayellowsubmarine"))

(def n (xsalsa20poly1305/generate-nonce))

(def p (.getBytes "this is a test"))

(def c (xsalsa20poly1305/seal k n p))

(prn (xsalsa20poly1305/unseal k n c))
```

## License

Copyright © 2017 Coda Hale

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
