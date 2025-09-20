;; Identity Registry Contract
;; Decentralized registry for verified digital identities

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-unauthorized (err u101))
(define-constant err-invalid-identity (err u102))
(define-constant err-identity-exists (err u103))
(define-constant err-identity-not-found (err u104))
(define-constant err-invalid-proof (err u105))
(define-constant err-insufficient-attestations (err u106))
(define-constant err-recovery-not-allowed (err u107))
(define-constant err-invalid-guardian (err u108))

;; Data variables
(define-data-var registry-admin principal tx-sender)
(define-data-var min-attestations uint u3)
(define-data-var next-identity-id uint u1)
(define-data-var recovery-period uint u144) ;; blocks (~24 hours)

;; Identity data structures
(define-map identities principal {
  id: uint,
  did: (string-ascii 64),
  verification-status: (string-ascii 20),
  reputation-score: uint,
  creation-timestamp: uint,
  last-updated: uint,
  recovery-address: (optional principal),
  is-active: bool
})

;; Identity attributes (private by default)
(define-map identity-attributes { identity: principal, attribute-type: (string-ascii 32) } {
  value-hash: (buff 32),
  is-public: bool,
  attestations: uint,
  expiration: uint
})

;; Attestation system
(define-map attestations uint {
  attester: principal,
  subject: principal,
  attribute-type: (string-ascii 32),
  confidence-score: uint,
  attestation-timestamp: uint,
  expiration: uint,
  is-revoked: bool
})

(define-data-var next-attestation-id uint u1)

;; Trusted attesters registry
(define-map trusted-attesters principal {
  is-trusted: bool,
  trust-level: uint,
  specializations: (list 10 (string-ascii 32)),
  attestation-count: uint
})

;; Identity recovery system
(define-map recovery-requests uint {
  identity: principal,
  new-address: principal,
  guardian: principal,
  request-timestamp: uint,
  approvals: uint,
  is-executed: bool
})

(define-data-var next-recovery-id uint u1)

;; Identity guardians
(define-map identity-guardians { identity: principal, guardian: principal } {
  trust-level: uint,
  added-timestamp: uint,
  is-active: bool
})

;; Reputation system
(define-map reputation-history uint {
  identity: principal,
  action: (string-ascii 32),
  score-change: int,
  timestamp: uint,
  reason: (string-ascii 64)
})

(define-data-var next-reputation-id uint u1)

;; Administrative functions
(define-public (set-registry-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (var-set registry-admin new-admin))
  )
)

(define-public (add-trusted-attester (attester principal) (trust-level uint) (specializations (list 10 (string-ascii 32))))
  (begin
    (asserts! (or (is-eq tx-sender contract-owner) (is-eq tx-sender (var-get registry-admin))) err-unauthorized)
    (asserts! (<= trust-level u100) err-invalid-proof)
    (ok (map-set trusted-attesters attester {
      is-trusted: true,
      trust-level: trust-level,
      specializations: specializations,
      attestation-count: u0
    }))
  )
)

;; Identity registration
(define-public (register-identity (did (string-ascii 64)) (recovery-address (optional principal)))
  (let
    (
      (identity-id (var-get next-identity-id))
      (existing-identity (map-get? identities tx-sender))
    )
    (asserts! (is-none existing-identity) err-identity-exists)
    (asserts! (> (len did) u0) err-invalid-identity)
    
    ;; Create identity record
    (map-set identities tx-sender {
      id: identity-id,
      did: did,
      verification-status: "unverified",
      reputation-score: u50,
      creation-timestamp: block-height,
      last-updated: block-height,
      recovery-address: recovery-address,
      is-active: true
    })
    
    ;; Record reputation event
    (map-set reputation-history (var-get next-reputation-id) {
      identity: tx-sender,
      action: "identity-created",
      score-change: 50,
      timestamp: block-height,
      reason: "Initial identity registration"
    })
    
    (var-set next-identity-id (+ identity-id u1))
    (var-set next-reputation-id (+ (var-get next-reputation-id) u1))
    (ok identity-id)
  )
)

;; Add identity attribute
(define-public (add-identity-attribute (attribute-type (string-ascii 32)) (value-hash (buff 32)) (is-public bool) (expiration uint))
  (let
    (
      (identity-data (unwrap! (map-get? identities tx-sender) err-identity-not-found))
      (attribute-key { identity: tx-sender, attribute-type: attribute-type })
    )
    (asserts! (get is-active identity-data) err-invalid-identity)
    (asserts! (> expiration block-height) err-invalid-proof)
    
    ;; Add attribute
    (map-set identity-attributes attribute-key {
      value-hash: value-hash,
      is-public: is-public,
      attestations: u0,
      expiration: expiration
    })
    
    ;; Update identity timestamp
    (map-set identities tx-sender (merge identity-data { last-updated: block-height }))
    
    (ok true)
  )
)

;; Attest to identity attribute
(define-public (attest-attribute (subject principal) (attribute-type (string-ascii 32)) (confidence-score uint) (expiration uint))
  (let
    (
      (attestation-id (var-get next-attestation-id))
      (attester-data (map-get? trusted-attesters tx-sender))
      (subject-identity (unwrap! (map-get? identities subject) err-identity-not-found))
      (attribute-key { identity: subject, attribute-type: attribute-type })
      (current-attribute (map-get? identity-attributes attribute-key))
    )
    (asserts! (is-some attester-data) err-unauthorized)
    (asserts! (get is-trusted (unwrap! attester-data err-unauthorized)) err-unauthorized)
    (asserts! (<= confidence-score u100) err-invalid-proof)
    (asserts! (> expiration block-height) err-invalid-proof)
    (asserts! (is-some current-attribute) err-invalid-identity)
    
    ;; Create attestation
    (map-set attestations attestation-id {
      attester: tx-sender,
      subject: subject,
      attribute-type: attribute-type,
      confidence-score: confidence-score,
      attestation-timestamp: block-height,
      expiration: expiration,
      is-revoked: false
    })
    
    ;; Update attribute attestation count
    (let
      (
        (attr-data (unwrap! current-attribute err-invalid-identity))
        (new-attestations (+ (get attestations attr-data) u1))
      )
      (map-set identity-attributes attribute-key (merge attr-data { attestations: new-attestations }))
      
      ;; Update verification status if enough attestations
      (if (>= new-attestations (var-get min-attestations))
        (map-set identities subject (merge subject-identity { 
          verification-status: "verified",
          reputation-score: (+ (get reputation-score subject-identity) u10)
        }))
        true
      )
    )
    
    ;; Update attester stats
    (map-set trusted-attesters tx-sender 
      (merge (unwrap! attester-data err-unauthorized) { 
        attestation-count: (+ (get attestation-count (unwrap! attester-data err-unauthorized)) u1) 
      })
    )
    
    (var-set next-attestation-id (+ attestation-id u1))
    (ok attestation-id)
  )
)

;; Add identity guardian
(define-public (add-guardian (guardian principal) (trust-level uint))
  (let
    (
      (identity-data (unwrap! (map-get? identities tx-sender) err-identity-not-found))
      (guardian-key { identity: tx-sender, guardian: guardian })
    )
    (asserts! (get is-active identity-data) err-invalid-identity)
    (asserts! (<= trust-level u100) err-invalid-guardian)
    (asserts! (not (is-eq tx-sender guardian)) err-invalid-guardian)
    
    (map-set identity-guardians guardian-key {
      trust-level: trust-level,
      added-timestamp: block-height,
      is-active: true
    })
    
    (ok true)
  )
)

;; Initiate identity recovery
(define-public (initiate-recovery (identity principal) (new-address principal))
  (let
    (
      (recovery-id (var-get next-recovery-id))
      (identity-data (unwrap! (map-get? identities identity) err-identity-not-found))
      (guardian-data (map-get? identity-guardians { identity: identity, guardian: tx-sender }))
    )
    (asserts! (is-some guardian-data) err-invalid-guardian)
    (asserts! (get is-active (unwrap! guardian-data err-invalid-guardian)) err-invalid-guardian)
    (asserts! (not (is-eq identity new-address)) err-invalid-identity)
    
    ;; Create recovery request
    (map-set recovery-requests recovery-id {
      identity: identity,
      new-address: new-address,
      guardian: tx-sender,
      request-timestamp: block-height,
      approvals: u1,
      is-executed: false
    })
    
    (var-set next-recovery-id (+ recovery-id u1))
    (ok recovery-id)
  )
)

;; Revoke attestation
(define-public (revoke-attestation (attestation-id uint))
  (let
    (
      (attestation-data (unwrap! (map-get? attestations attestation-id) err-invalid-proof))
    )
    (asserts! (is-eq tx-sender (get attester attestation-data)) err-unauthorized)
    (asserts! (not (get is-revoked attestation-data)) err-invalid-proof)
    
    ;; Revoke attestation
    (map-set attestations attestation-id (merge attestation-data { is-revoked: true }))
    
    ;; Update subject's reputation
    (let
      (
        (subject-identity (unwrap! (map-get? identities (get subject attestation-data)) err-identity-not-found))
        (reputation-id (var-get next-reputation-id))
      )
      (map-set identities (get subject attestation-data) 
        (merge subject-identity { reputation-score: (- (get reputation-score subject-identity) u5) })
      )
      
      ;; Record reputation change
      (map-set reputation-history reputation-id {
        identity: (get subject attestation-data),
        action: "attestation-revoked",
        score-change: -5,
        timestamp: block-height,
        reason: "Attestation was revoked by attester"
      })
      
      (var-set next-reputation-id (+ reputation-id u1))
    )
    
    (ok true)
  )
)

;; Read-only functions
(define-read-only (get-identity (identity principal))
  (map-get? identities identity)
)

(define-read-only (get-identity-attribute (identity principal) (attribute-type (string-ascii 32)))
  (map-get? identity-attributes { identity: identity, attribute-type: attribute-type })
)

(define-read-only (get-attestation (attestation-id uint))
  (map-get? attestations attestation-id)
)

(define-read-only (get-trusted-attester (attester principal))
  (map-get? trusted-attesters attester)
)

(define-read-only (get-recovery-request (recovery-id uint))
  (map-get? recovery-requests recovery-id)
)

(define-read-only (get-identity-guardian (identity principal) (guardian principal))
  (map-get? identity-guardians { identity: identity, guardian: guardian })
)

(define-read-only (get-reputation-history (reputation-id uint))
  (map-get? reputation-history reputation-id)
)

(define-read-only (is-identity-verified (identity principal))
  (match (map-get? identities identity)
    identity-data (is-eq (get verification-status identity-data) "verified")
    false
  )
)

;; Initialize contract
(begin
  (map-set trusted-attesters contract-owner {
    is-trusted: true,
    trust-level: u100,
    specializations: (list "general" "admin"),
    attestation-count: u0
  })
)


;; title: identity-registry
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

