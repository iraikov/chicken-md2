;;; md2.scm - Message Digest 2 algorithm as defined in RFC 1319
;;;
;;;
;;; Copyright (C) 2018, Tobias Heilig
;;; All rights reserved.
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;; 1. Redistributions of source code must retain the above copyright
;;;    notice, this list of conditions and the following disclaimer.
;;;
;;; 2. Redistributions in binary form must reproduce the above copyright
;;;    notice, this list of conditions and the following disclaimer in the
;;;    documentation and/or other materials provided with the distribution.
;;;
;;; 3. Neither the name of the authors nor the names of its contributors
;;;    may be used to endorse or promote products derived from this
;;;    software without specific prior written permission.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;; TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;
;;;
;;; https://ietf.org/rfc/rfc1319.txt



(module md2

        (md2-primitive)


  (import scheme (chicken base)
          (chicken foreign)
          srfi-1 srfi-4 srfi-13
          message-digest)


  #>#include "md2-base.c"<#


  (define block-length  (foreign-value "MD2_BLOCK_SIZE"  unsigned-int))
  (define digest-length (foreign-value "MD2_DIGEST_LEN"  unsigned-int))
  (define context-size  (foreign-value "sizeof(MD2_CTX)" unsigned-int))

  (define init       (foreign-lambda void MD2_Init c-pointer))
  (define update     (foreign-lambda void MD2_Update c-pointer scheme-pointer unsigned-int))
  (define raw-update (foreign-lambda void MD2_Update c-pointer c-pointer unsigned-int))
  (define final      (foreign-lambda void MD2_Final c-pointer scheme-pointer))


  (define md2-primitive
    (let ((the-md2-primitive #f))
      (lambda ()
        (unless the-md2-primitive
          (set!
            the-md2-primitive
            (make-message-digest-primitive
              context-size
              digest-length
              init
              update
              final
              block-length
              'md2-primitive
              raw-update)))
        the-md2-primitive))))

