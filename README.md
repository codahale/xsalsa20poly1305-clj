# xsalsa20poly1305

A Clojure wrapper for encryption with XSalsa20Poly1305, compatible with DJB's
NaCl.

## Usage

```clojure
(require '[xsalsa20poly1305.core :as xsalsa])

(def k (into-array Byte/TYPE "ayellowsubmarineayellowsubmarine"))

(def p (into-array Byte/TYPE "this is a test"))

(def c (seal k p))

(prn (unseal k c))
```

## License

Copyright © 2017 Coda Hale

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
