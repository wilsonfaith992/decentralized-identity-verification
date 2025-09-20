;; Credential Verification Contract
;; Smart contract for verifying and issuing digital credentials

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u200))
(define-constant err-unauthorized (err u201))
(define-constant err-invalid-credential (err u202))
(define-constant err-credential-not-found (err u203))
(define-constant err-credential-expired (err u204))
(define-constant err-credential-revoked (err u205))
(define-constant err-insufficient-signatures (err u206))
(define-constant err-invalid-issuer (err u207))
(define-constant err-invalid-schema (err u208))

;; Data variables
(define-data-var credential-admin principal tx-sender)
(define-data-var min-issuer-signatures uint u2)
(define-data-var next-credential-id uint u1)
(define-data-var next-schema-id uint u1)

;; Credential data structures
(define-map credentials uint {
  id: uint,
  holder: principal,
  issuer: principal,
  credential-type: (string-ascii 32),
  schema-id: uint,
  credential-hash: (buff 32),
  issued-timestamp: uint,
  expiration-timestamp: uint,
  is-revoked: bool,
  verification-count: uint
})

;; Credential schemas
(define-map credential-schemas uint {
  schema-name: (string-ascii 64),
  version: (string-ascii 16),
  fields: (list 20 (string-ascii 32)),
  required-signatures: uint,
  created-by: principal,
  creation-timestamp: uint,
  is-active: bool
})

;; Authorized issuers
(define-map authorized-issuers principal {
  is-authorized: bool,
  authorization-level: uint,
  allowed-schemas: (list 10 uint),
  issued-count: uint,
  reputation-score: uint,
  authorized-timestamp: uint
})

;; Credential signatures
(define-map credential-signatures { credential-id: uint, signer: principal } {
  signature-hash: (buff 32),
  signature-timestamp: uint,
  is-valid: bool
})

;; Verification requests
(define-map verification-requests uint {
  credential-id: uint,
  verifier: principal,
  verification-purpose: (string-ascii 64),
  request-timestamp: uint,
  verification-result: (string-ascii 20),
  is-completed: bool
})

(define-data-var next-verification-id uint u1)

;; Revocation registry
(define-map revocation-registry uint {
  credential-id: uint,
  revoked-by: principal,
  revocation-reason: (string-ascii 64),
  revocation-timestamp: uint,
  is-permanent: bool
})

(define-data-var next-revocation-id uint u1)

;; Credential templates
(define-map credential-templates uint {
  template-name: (string-ascii 64),
  template-type: (string-ascii 32),
  required-fields: (list 15 (string-ascii 32)),
  validation-rules: (string-ascii 128),
  created-by: principal,
  is-public: bool
})

(define-data-var next-template-id uint u1)

;; Administrative functions
(define-public (set-credential-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (var-set credential-admin new-admin))
  )
)

(define-public (authorize-issuer (issuer principal) (authorization-level uint) (allowed-schemas (list 10 uint)))
  (begin
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (var-get credential-admin))) err-unauthorized)
    (asserts! (<= authorization-level u100) err-invalid-issuer)
    (ok (map-set authorized-issuers issuer {
      is-authorized: true,
      authorization-level: authorization-level,
      allowed-schemas: allowed-schemas,
      issued-count: u0,
      reputation-score: u100,
      authorized-timestamp: block-height
    }))
  )
)

;; Schema management
(define-public (create-credential-schema (schema-name (string-ascii 64)) (version (string-ascii 16)) (fields (list 20 (string-ascii 32))) (required-signatures uint))
  (let
    (
      (schema-id (var-get next-schema-id))
      (issuer-data (map-get? authorized-issuers tx-sender))
    )
    (asserts! (is-some issuer-data) err-unauthorized)
    (asserts! (get is-authorized (unwrap! issuer-data err-unauthorized)) err-unauthorized)
    (asserts! (>= (get authorization-level (unwrap! issuer-data err-unauthorized)) u50) err-unauthorized)
    (asserts! (> required-signatures u0) err-invalid-schema)
    (asserts! (> (len fields) u0) err-invalid-schema)
    
    ;; Create schema
    (map-set credential-schemas schema-id {
      schema-name: schema-name,
      version: version,
      fields: fields,
      required-signatures: required-signatures,
      created-by: tx-sender,
      creation-timestamp: block-height,
      is-active: true
    })
    
    (var-set next-schema-id (+ schema-id u1))
    (ok schema-id)
  )
)

;; Credential issuance
(define-public (issue-credential (holder principal) (credential-type (string-ascii 32)) (schema-id uint) (credential-hash (buff 32)) (expiration-timestamp uint))
  (let
    (
      (credential-id (var-get next-credential-id))
      (issuer-data (unwrap! (map-get? authorized-issuers tx-sender) err-unauthorized))
      (schema-data (unwrap! (map-get? credential-schemas schema-id) err-invalid-schema))
    )
    (asserts! (get is-authorized issuer-data) err-unauthorized)
    (asserts! (get is-active schema-data) err-invalid-schema)
    (asserts! (> expiration-timestamp block-height) err-invalid-credential)
    
    ;; Check if issuer is allowed to use this schema
    (asserts! (is-some (index-of (get allowed-schemas issuer-data) schema-id)) err-unauthorized)
    
    ;; Create credential
    (map-set credentials credential-id {
      id: credential-id,
      holder: holder,
      issuer: tx-sender,
      credential-type: credential-type,
      schema-id: schema-id,
      credential-hash: credential-hash,
      issued-timestamp: block-height,
      expiration-timestamp: expiration-timestamp,
      is-revoked: false,
      verification-count: u0
    })
    
    ;; Update issuer statistics
    (map-set authorized-issuers tx-sender (merge issuer-data {
      issued-count: (+ (get issued-count issuer-data) u1)
    }))
    
    (var-set next-credential-id (+ credential-id u1))
    (ok credential-id)
  )
)

;; Multi-signature credential signing
(define-public (sign-credential (credential-id uint) (signature-hash (buff 32)))
  (let
    (
      (credential-data (unwrap! (map-get? credentials credential-id) err-credential-not-found))
      (issuer-data (map-get? authorized-issuers tx-sender))
      (signature-key { credential-id: credential-id, signer: tx-sender })
    )
    (asserts! (is-some issuer-data) err-unauthorized)
    (asserts! (get is-authorized (unwrap! issuer-data err-unauthorized)) err-unauthorized)
    (asserts! (not (get is-revoked credential-data)) err-credential-revoked)
    
    ;; Add signature
    (map-set credential-signatures signature-key {
      signature-hash: signature-hash,
      signature-timestamp: block-height,
      is-valid: true
    })
    
    (ok true)
  )
)

;; Credential verification
(define-public (verify-credential (credential-id uint) (verification-purpose (string-ascii 64)))
  (let
    (
      (verification-id (var-get next-verification-id))
      (credential-data (unwrap! (map-get? credentials credential-id) err-credential-not-found))
    )
    (asserts! (not (get is-revoked credential-data)) err-credential-revoked)
    (asserts! (> (get expiration-timestamp credential-data) block-height) err-credential-expired)
    
    ;; Create verification request
    (map-set verification-requests verification-id {
      credential-id: credential-id,
      verifier: tx-sender,
      verification-purpose: verification-purpose,
      request-timestamp: block-height,
      verification-result: "verified",
      is-completed: true
    })
    
    ;; Update credential verification count
    (map-set credentials credential-id (merge credential-data {
      verification-count: (+ (get verification-count credential-data) u1)
    }))
    
    (var-set next-verification-id (+ verification-id u1))
    (ok verification-id)
  )
)

;; Credential revocation
(define-public (revoke-credential (credential-id uint) (revocation-reason (string-ascii 64)) (is-permanent bool))
  (let
    (
      (revocation-id (var-get next-revocation-id))
      (credential-data (unwrap! (map-get? credentials credential-id) err-credential-not-found))
      (issuer-data (map-get? authorized-issuers tx-sender))
    )
    (asserts! (or 
      (is-eq tx-sender (get issuer credential-data)) 
      (and (is-some issuer-data) (>= (get authorization-level (unwrap! issuer-data err-unauthorized)) u80))
    ) err-unauthorized)
    (asserts! (not (get is-revoked credential-data)) err-credential-revoked)
    
    ;; Revoke credential
    (map-set credentials credential-id (merge credential-data { is-revoked: true }))
    
    ;; Record revocation
    (map-set revocation-registry revocation-id {
      credential-id: credential-id,
      revoked-by: tx-sender,
      revocation-reason: revocation-reason,
      revocation-timestamp: block-height,
      is-permanent: is-permanent
    })
    
    (var-set next-revocation-id (+ revocation-id u1))
    (ok revocation-id)
  )
)

;; Create credential template
(define-public (create-credential-template (template-name (string-ascii 64)) (template-type (string-ascii 32)) (required-fields (list 15 (string-ascii 32))) (validation-rules (string-ascii 128)) (is-public bool))
  (let
    (
      (template-id (var-get next-template-id))
      (issuer-data (map-get? authorized-issuers tx-sender))
    )
    (asserts! (is-some issuer-data) err-unauthorized)
    (asserts! (get is-authorized (unwrap! issuer-data err-unauthorized)) err-unauthorized)
    (asserts! (> (len required-fields) u0) err-invalid-credential)
    
    ;; Create template
    (map-set credential-templates template-id {
      template-name: template-name,
      template-type: template-type,
      required-fields: required-fields,
      validation-rules: validation-rules,
      created-by: tx-sender,
      is-public: is-public
    })
    
    (var-set next-template-id (+ template-id u1))
    (ok template-id)
  )
)

;; Batch credential verification
(define-public (batch-verify-credentials (credential-ids (list 10 uint)) (verification-purpose (string-ascii 64)))
  (let
    (
      (verification-results (map verify-single-credential credential-ids))
    )
    (ok verification-results)
  )
)

;; Helper function for batch verification
(define-private (verify-single-credential (credential-id uint))
  (let
    (
      (credential-data (map-get? credentials credential-id))
    )
    (match credential-data
      cred-data {
        credential-id: credential-id,
        is-valid: (and 
          (not (get is-revoked cred-data))
          (> (get expiration-timestamp cred-data) block-height)
        )
      }
      { credential-id: credential-id, is-valid: false }
    )
  )
)

;; Update issuer reputation
(define-public (update-issuer-reputation (issuer principal) (reputation-change int))
  (let
    (
      (issuer-data (unwrap! (map-get? authorized-issuers issuer) err-invalid-issuer))
      (current-reputation (get reputation-score issuer-data))
      (new-reputation (if (> reputation-change 0) 
        (+ current-reputation (to-uint reputation-change))
        (- current-reputation (to-uint (- 0 reputation-change)))
      ))
    )
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (var-get credential-admin))) err-unauthorized)
    
    (map-set authorized-issuers issuer (merge issuer-data {
      reputation-score: (if (> new-reputation u100) u100 new-reputation)
    }))
    
    (ok new-reputation)
  )
)

;; Read-only functions
(define-read-only (get-credential (credential-id uint))
  (map-get? credentials credential-id)
)

(define-read-only (get-credential-schema (schema-id uint))
  (map-get? credential-schemas schema-id)
)

(define-read-only (get-authorized-issuer (issuer principal))
  (map-get? authorized-issuers issuer)
)

(define-read-only (get-credential-signature (credential-id uint) (signer principal))
  (map-get? credential-signatures { credential-id: credential-id, signer: signer })
)

(define-read-only (get-verification-request (verification-id uint))
  (map-get? verification-requests verification-id)
)

(define-read-only (get-revocation-record (revocation-id uint))
  (map-get? revocation-registry revocation-id)
)

(define-read-only (get-credential-template (template-id uint))
  (map-get? credential-templates template-id)
)

(define-read-only (is-credential-valid (credential-id uint))
  (match (map-get? credentials credential-id)
    credential-data {
      valid: (and 
        (not (get is-revoked credential-data))
        (> (get expiration-timestamp credential-data) block-height)
      ),
      expired: (<= (get expiration-timestamp credential-data) block-height),
      revoked: (get is-revoked credential-data)
    }
    { valid: false, expired: false, revoked: false }
  )
)

;; Initialize contract
(begin
  (map-set authorized-issuers contract-owner {
    is-authorized: true,
    authorization-level: u100,
    allowed-schemas: (list u1 u2 u3 u4 u5),
    issued-count: u0,
    reputation-score: u100,
    authorized-timestamp: block-height
  })
)


;; title: credential-verification
;; version:
;; summary:
;; description:

;; traits
;;

;; token definitions
;;

;; constants
;;

;; data vars
;;

;; data maps
;;

;; public functions
;;

;; read only functions
;;

;; private functions
;;

