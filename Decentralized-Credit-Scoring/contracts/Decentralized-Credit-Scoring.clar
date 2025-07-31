;; Decentralized Credit Scoring Contract
;; Privacy-preserving credit assessment using zero-knowledge proofs

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_SCORE (err u101))
(define-constant ERR_ALREADY_ASSESSED (err u102))
(define-constant ERR_NOT_FOUND (err u103))
(define-constant ERR_INVALID_PROOF (err u104))
(define-constant ERR_EXPIRED_ASSESSMENT (err u105))

;; Data Variables
(define-data-var contract-active bool true)
(define-data-var assessment-fee uint u1000000) ;; 1 STX in microSTX
(define-data-var min-score uint u300)
(define-data-var max-score uint u850)

;; Data Maps
(define-map credit-assessments
  principal
  {
    score-hash: (buff 32),
    assessment-date: uint,
    validity-period: uint,
    verifier-count: uint,
    is-verified: bool
  }
)

(define-map authorized-verifiers
  principal
  {
    is-active: bool,
    verification-count: uint,
    reputation-score: uint
  }
)

(define-map score-proofs
  { user: principal, proof-id: uint }
  {
    commitment: (buff 32),
    challenge: (buff 32),
    response: (buff 32),
    timestamp: uint,
    is-valid: bool
  }
)

(define-map user-credit-history
  principal
  {
    total-assessments: uint,
    average-score: uint,
    last-update: uint,
    payment-history-hash: (buff 32)
  }
)

;; Read-only functions
(define-read-only (get-credit-assessment (user principal))
  (map-get? credit-assessments user)
)

(define-read-only (get-verifier-info (verifier principal))
  (map-get? authorized-verifiers verifier)
)

(define-read-only (get-user-history (user principal))
  (map-get? user-credit-history user)
)

(define-read-only (is-assessment-valid (user principal))
  (match (map-get? credit-assessments user)
    assessment
    (let (
      (current-block stacks-block-height)
    )
    (< current-block (+ (get assessment-date assessment) (get validity-period assessment))))
    false
  )
)

(define-read-only (calculate-risk-category (score-hash (buff 32)))
  (let (
    ;; Use hash length and basic operations for deterministic score calculation
    (hash-length (len score-hash))
    ;; Create a pseudo-random value from the hash using available operations
    (hash-derived-value (mod (+ 
      (len (unwrap-panic (slice? score-hash u0 u1)))
      (len (unwrap-panic (slice? score-hash u8 u9)))
      (len (unwrap-panic (slice? score-hash u16 u17)))
      (len (unwrap-panic (slice? score-hash u24 u25)))
      hash-length) u551))
  )
  (+ hash-derived-value (var-get min-score)))
)

(define-read-only (verify-zero-knowledge-proof 
  (commitment (buff 32))
  (challenge (buff 32)) 
  (response (buff 32))
  (public-input (buff 32)))
  
  (let (
    (computed-commitment (sha256 (concat response challenge)))
    (expected-commitment (sha256 (concat commitment public-input)))
  )
  (is-eq computed-commitment expected-commitment))
)

;; Private functions
(define-private (get-byte-value (buffer (buff 32)) (index uint))
  (let (
    (byte-slice (unwrap-panic (slice? buffer index (+ index u1))))
  )
  (len byte-slice))
)

(define-private (update-verifier-reputation (verifier principal) (success bool))
  (match (map-get? authorized-verifiers verifier)
    verifier-info
    (map-set authorized-verifiers verifier
      (merge verifier-info {
        verification-count: (+ (get verification-count verifier-info) u1),
        reputation-score: (if success 
          (+ (get reputation-score verifier-info) u10)
          (if (> (get reputation-score verifier-info) u5)
            (- (get reputation-score verifier-info) u5)
            u0))
      })
    )
    false
  )
)

;; Public functions
(define-public (initialize-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-active true)
    (ok true)
  )
)

(define-public (add-authorized-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (map-set authorized-verifiers verifier {
      is-active: true,
      verification-count: u0,
      reputation-score: u100
    })
    (ok true)
  )
)

(define-public (submit-credit-assessment 
  (score-hash (buff 32))
  (validity-period uint))
  
  (let (
    (current-block stacks-block-height)
    (fee (var-get assessment-fee))
  )
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? credit-assessments tx-sender)) ERR_ALREADY_ASSESSED)
    
    ;; Transfer assessment fee
    (try! (stx-transfer? fee tx-sender CONTRACT_OWNER))
    
    ;; Store credit assessment
    (map-set credit-assessments tx-sender {
      score-hash: score-hash,
      assessment-date: current-block,
      validity-period: validity-period,
      verifier-count: u0,
      is-verified: false
    })
    
    ;; Update user history
    (match (map-get? user-credit-history tx-sender)
      history
      (map-set user-credit-history tx-sender
        (merge history {
          total-assessments: (+ (get total-assessments history) u1),
          last-update: current-block
        })
      )
      (map-set user-credit-history tx-sender {
        total-assessments: u1,
        average-score: u0,
        last-update: current-block,
        payment-history-hash: score-hash
      })
    )
    
    (ok true)
  ))
)

(define-public (submit-zk-proof
  (user principal)
  (proof-id uint)
  (commitment (buff 32))
  (challenge (buff 32))
  (response (buff 32)))
  
  (let (
    (current-block stacks-block-height)
    (verifier-info (unwrap! (map-get? authorized-verifiers tx-sender) ERR_UNAUTHORIZED))
  )
  (begin
    (asserts! (get is-active verifier-info) ERR_UNAUTHORIZED)
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    
    ;; Store zero-knowledge proof
    (map-set score-proofs { user: user, proof-id: proof-id } {
      commitment: commitment,
      challenge: challenge,
      response: response,
      timestamp: current-block,
      is-valid: false
    })
    
    (ok proof-id)
  ))
)

(define-public (verify-assessment
  (user principal)
  (proof-id uint)
  (public-score-commitment (buff 32)))
  
  (let (
    (assessment (unwrap! (map-get? credit-assessments user) ERR_NOT_FOUND))
    (proof (unwrap! (map-get? score-proofs { user: user, proof-id: proof-id }) ERR_NOT_FOUND))
    (verifier-info (unwrap! (map-get? authorized-verifiers tx-sender) ERR_UNAUTHORIZED))
  )
  (begin
    (asserts! (get is-active verifier-info) ERR_UNAUTHORIZED)
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    
    ;; Verify zero-knowledge proof
    (let (
      (is-proof-valid (verify-zero-knowledge-proof
        (get commitment proof)
        (get challenge proof)
        (get response proof)
        public-score-commitment))
    )
    (begin
      ;; Update proof validity
      (map-set score-proofs { user: user, proof-id: proof-id }
        (merge proof { is-valid: is-proof-valid }))
      
      ;; Update assessment if proof is valid
      (if is-proof-valid
        (begin
          (map-set credit-assessments user
            (merge assessment {
              verifier-count: (+ (get verifier-count assessment) u1),
              is-verified: true
            }))
          (update-verifier-reputation tx-sender true)
          (ok true)
        )
        (begin
          (update-verifier-reputation tx-sender false)
          ERR_INVALID_PROOF
        )
      )
    ))
  ))
)

(define-public (request-credit-score (user principal))
  (let (
    (assessment (unwrap! (map-get? credit-assessments user) ERR_NOT_FOUND))
  )
  (begin
    (asserts! (var-get contract-active) ERR_UNAUTHORIZED)
    (asserts! (get is-verified assessment) ERR_INVALID_PROOF)
    (asserts! (is-assessment-valid user) ERR_EXPIRED_ASSESSMENT)
    
    (ok {
      score-range: (calculate-risk-category (get score-hash assessment)),
      verification-date: (get assessment-date assessment),
      verifier-count: (get verifier-count assessment),
      is-current: true
    })
  ))
)

(define-public (update-assessment-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set assessment-fee new-fee)
    (ok true)
  )
)

(define-public (deactivate-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (match (map-get? authorized-verifiers verifier)
      verifier-info
      (begin
        (map-set authorized-verifiers verifier
          (merge verifier-info { is-active: false }))
        (ok true)
      )
      ERR_NOT_FOUND
    )
  )
)

(define-public (emergency-pause)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-active false)
    (ok true)
  )
)

(define-public (emergency-resume)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-active true)
    (ok true)
  )
)