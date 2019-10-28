(ns asn-1-parser.core
  (:gen-class)
  (:require [clojure.string  :as str]
            [clojure.java.io :as io]
            [clojure.pprint  :refer [pprint]])
  (:import java.io.RandomAccessFile
           java.nio.ByteBuffer
           java.nio.BufferUnderflowException
           javax.xml.bind.DatatypeConverter
           java.lang.Byte
           java.lang.String))

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

(def tag-map {0x02 {:type :primitive :name "INTEGER"}
              0x03 {:type :primitive :name "BIT STRING"}
              0x01 {:type :primitive :name "BOOLEAN"}
              0x05 {:type :primitive :name "NULL"}
              0x06 {:type :primitive :name "OBJECT IDENTIFIER"}
              0x04 {:type :primitive :name "OCTET STRING"}
              0x1E {:type :primitive :name "BMPString"}
              0x16 {:type :primitive :name "IA5String"}
              0x13 {:type :primitive :name "PrintableString"}
              0x14 {:type :primitive :name "TeletexString"}
              0x0C {:type :primitive :name "UTF8String"}
              0x30 {:type :constructed :name "SEQUENCE"}
              0x31 {:type :constructed :name "SET"}})

(def private-key-data-example
  {:version "1"
   :modulus 12
   :publicExponent 32
   :privateExponent 903
   :prime1 321
   :prime2 123
   :exponent1 543
   :exponent2 654
   :coefficient 3982})

(defn next-byte
  [bb]
  (try (.get bb)
       (catch BufferUnderflowException e
         ;; we're at the end of the byte buffer
         nil)))

(defn next-tlv-tag
  [bb]
  (next-byte bb))

(def bytes->short
  (comp #(.getShort %) #(ByteBuffer/wrap %) byte-array))

(def bytes->long
  (comp #(.getLong %) #(ByteBuffer/wrap %) byte-array))

(defn to-hex-seq
  [bytes]
  (reduce #(str %1 (format "%02X" %2))
          ""
          bytes))

(defn to-hex
  [byte]
  (format "%x" byte))

(defn bytes->integer
  [n-bytes bytes-seq]
  (let [convertion-fn (cond
                        (>= n-bytes 8) bytes->long
                        (>= n-bytes 2) bytes->short
                        :else #(bytes->short 2 (cons (byte 0) %2)))]
    (when convertion-fn
      (convertion-fn n-bytes bytes-seq))))

(defn next-tlv-length
  [bb]
  (when-let [byte (next-byte bb)]
    (let [length>127? (= 128 (bit-and byte 128))
          length (bit-and byte 127)]
      (if length>127?
        (let [actual-length (take length
                                  (repeatedly #(next-byte bb)))]
          (bytes->integer length actual-length))
        length))))

(defn next-tlv-value
  "Returns the next n bytes from the byte buffer."
  [bb length]
  (take length
        (repeatedly #(next-byte bb))))

(defn next-tlv
  "This function returns the next TLV triple."
  [bb]
  (let [tag (next-tlv-tag bb)
        tag-type (tag-map tag)
        length (next-tlv-length bb)]
    (when length
      {:type (or tag-type (to-hex tag))
       :length length
       :value (do
                (cond
                  (= :constructed (:type tag-type)) ::sequence-value
                  (= :primitive (:type tag-type)) (to-hex-seq (next-tlv-value bb length))
                  (nil? tag-type) ::not-known-tag
                  :else ::not-processed-tag))})))

(defn tlv-sequence?
  [tlv]
  (= :constructed (:type (:type tlv))))

(def not-tlv-sequence? (complement tlv-sequence?))

(defn parse-asn1
  "This currently only parses a RSA private key.
   A RSA PK is a SEQUENCE containing the following fields:
     - version           Version,
     - modulus           INTEGER,  -- n
     - publicExponent    INTEGER,  -- e
     - privateExponent   INTEGER,  -- d
     - prime1            INTEGER,  -- p
     - prime2            INTEGER,  -- q
     - exponent1         INTEGER,  -- d mod (p-1)
     - exponent2         INTEGER,  -- d mod (q-1)
     - coefficient       INTEGER,  -- (inverse of q) mod p
     - otherPrimeInfos   OtherPrimeInfos OPTIONAL
   (source: https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem)"
  [bb result-seq]
  (let [tlv (next-tlv bb)]              ; GET THE FIRST TLV OF THE BB
    (if tlv
      (if (not-tlv-sequence? tlv)
        (conj result-seq tlv)             ; IF IT'S NOT A SEQ, RETURN THE CONJ OF TLV AND RESULT
        (reduce
         (fn [acc _]
           (concat acc (parse-asn1 bb [])))
         result-seq
         (range 0 (:length tlv))))
      result-seq)))

(defn -main [& args]
  (if-let [key-path (first args)]
    (pprint (parse-asn1 (base64-buffer key-path) []))
    (binding [*out* *err*]
      (println "no path given")
      (System/exit 1))))
