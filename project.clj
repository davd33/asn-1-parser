(defproject asn-1-parser "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [javax.xml.bind/jaxb-api "2.3.1"]]
  :main ^:skip-aot asn-1-parser.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
