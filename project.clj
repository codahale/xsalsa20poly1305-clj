(defproject com.codahale/xsalsa20poly1305 "0.4.2"
  :description "A Clojure implementation of XSalsa20Poly1305 authenticated encryption."
  :url "https://github.com/codahale/xsalsa20poly1305"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.56"]]
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :global-vars {*warn-on-reflection* true}
  :test-selectors {:default #(not-any? % [:bench])
                   :bench   :bench}
  :aliases {"bench" ["test" ":bench"]}
  :profiles {:dev           [:project/dev :profiles/dev]
             :test          [:project/test :profiles/test]
             :profiles/dev  {:dependencies [[org.clojure/clojure "1.8.0"]
                                            [buddy/buddy-core "1.2.0"]
                                            [caesium "0.9.0"]
                                            [criterium "0.4.4"]]}
             :profiles/test {}
             :project/dev   {:source-paths ["dev"]
                             :repl-options {:init-ns user}}
             :project/test  {:dependencies []}})
