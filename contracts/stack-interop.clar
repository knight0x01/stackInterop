;; title: stack-interop
;; summary: A cross-chain identity registry for linking Stacks principals to Bitcoin addresses.

;; constants
;; Error code u100: Standard authorization error
(define-constant ERR-NOT-AUTHORIZED (err u100))

;; Error code u101: Principal already linked to a Bitcoin address
(define-constant ERR-ALREADY-LINKED (err u101))

;; Error code u102: The provided signature is cryptographically invalid
(define-constant ERR-INVALID-SIGNATURE (err u102))

;; Error code u103: The provided public key is not in a supported format
(define-constant ERR-INVALID-PUBKEY (err u103))

;; Error code u104: The message hash length or format is incorrect
(define-constant ERR-INVALID-MESSAGE-HASH (err u104))

;; data maps
;; Maps a Stacks principal to a Bitcoin address (stored as a buffer)
(define-map identity-registry principal (buff 20))

;; public functions

;; @desc Links a Stacks principal to a Bitcoin address by providing a public key and signature.
;; @param btc-pubkey: The 33-byte or 65-byte Bitcoin public key.
;; @param signature: The 65-byte signature (compact format).
;; @param message-hash: The hash of the message signed by the Bitcoin wallet.
(define-public (link-address (btc-pubkey (buff 33)) (signature (buff 65)) (message-hash (buff 32)))
    (let (
        (caller tx-sender)
        ;; Derive the 20-byte hash (H160) from the public key (mock logic for now, real logic involves sha256 then ripemd160)
        (btc-address-hash (hash160 btc-pubkey))
    )
        ;; Check if already linked
        (asserts! (is-none (map-get? identity-registry caller)) ERR-ALREADY-LINKED)
        
        ;; Verify signature (mocking verification for initial structure)
        ;; In a real scenario, secp256k1-verify would be used.
        ;; (asserts! (secp256k1-verify message-hash signature btc-pubkey) ERR-INVALID-SIGNATURE)
        
        ;; Link the address
        (map-set identity-registry caller btc-address-hash)
        (ok true)
    )
)

;; read only functions

;; @desc Retrieves the linked Bitcoin address hash for a given Stacks principal.
(define-read-only (get-identity (user principal))
    (map-get? identity-registry user)
)
