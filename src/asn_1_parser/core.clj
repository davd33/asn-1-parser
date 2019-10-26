(ns asn-1-parser.core
  (:gen-class)
  (:require [clojure.string  :as str]
            [clojure.java.io :as io]
            [clojure.pprint  :refer [pprint]])
  (:import java.io.RandomAccessFile
           java.nio.ByteBuffer
           java.nio.BufferUnderflowException
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

(defn type-of
  [byte]
  (cond
    (= 0x30 byte) "SEQUENCE"
    (nil? byte) nil
    :else "NOT_HANDLED"))

(defn next-byte
  [bb]
  (try (.get bb)
       (catch BufferUnderflowException e
         ;; we're at the end of the byte buffer
         nil)))

(defn traverse-byte-buffer
  [bb f]
  (loop [types []]
    (let [next-value (f (next-byte bb))]
      (if (nil? next-value)
        types
        (recur
         (conj types next-value))))))

(defn parse-asn1
  [bb]
  (traverse-byte-buffer bb type-of))

(defn -main [& args]
  (if-let [key-path (first args)]
    (pprint (parse-asn1 (base64-buffer key-path)))
    (binding [*out* *err*]
      (println "no path given")
      (System/exit 1))))
