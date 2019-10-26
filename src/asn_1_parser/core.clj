(ns asn-1-parser.core
  (:gen-class)
  (:require [clojure.string  :as str]
            [clojure.java.io :as io]
            [clojure.pprint  :refer [pprint]])
  (:import java.io.RandomAccessFile
          java.nio.ByteBuffer
          javax.xml.bind.DatatypeConverter))

(defn base64-extract
  [path]
  (reduce str "" (remove #(str/starts-with? % "----") (line-seq (io/reader path)))))

(defn base64-bytes
  [path]
  (let [b64-str ^String (base64-extract path)]
    (DatatypeConverter/parseBase64Binary b64-str)))

(defn base64-buffer
  [path]
  (ByteBuffer/wrap (base64-bytes path)))

(defn parse-asn1
  [bb]
  ::nothing-parsed)

(defn -main [& args]
  (if-let [key-path (first args)]
    (pprint (parse-asn1 (base64-buffer key-path)))
    (binding [*out* *err*]
      (println "no path given")
      (System/exit 1))))
