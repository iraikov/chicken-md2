;;; Message Digest 2 (MD2) Algorithm
;;;
;;;             Tests




(use test message-digest md2)




;; verify test vectors as defined in RFC 1319
;;
;; see https://ietf.org/rfc/rfc1319.txt

(test-begin "MD2 Test Vectors")

(test-group "RFC 1319"

            (test "8350e5a3e24c153df2275c9f80692773"
                  (message-digest-string (md2-primitive) ""))

            (test "32ec01ec4a6dac72c0ab96fb34c0b5d1"
                  (message-digest-string (md2-primitive) "a"))

            (test "da853b0d3f88d99b30283a69e6ded6bb"
                  (message-digest-string (md2-primitive) "abc"))

            (test "ab4f496bfb2a530b219ff33031fe06b0"
                  (message-digest-string (md2-primitive) "message digest"))

            (test "4e8ddff3650292ab5a4108c3aa47940b"
                  (message-digest-string (md2-primitive) "abcdefghijklmnopqrstuvwxyz"))

            (test "da33def2a42df13975352846c30338cd"
                  (message-digest-string (md2-primitive) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
            (test "d5976f79d83d3a0dc9806c3c66f3efd8"
                  (message-digest-string (md2-primitive) "12345678901234567890123456789012345678901234567890123456789012345678901234567890")))

(test-end "MD2 Test Vectors")
