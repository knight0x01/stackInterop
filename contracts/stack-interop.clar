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

;; Administrative constants
;; The initial owner of the contract is the principal that deploys it.
(define-constant INITIAL-OWNER tx-sender)

;; Access control constants
;; Error code u105: The operation requires contract owner privileges
(define-constant ERR-NOT-OWNER (err u1005))

;; Error code u106: The contract is currently paused for maintenance
(define-constant ERR-PAUSED (err u1006))

;; Error code u107: The registry has reached its maximum allowed capacity
(define-constant ERR-LIMIT-REACHED (err u1007))

;; Scaling constants
;; Default maximum number of identities allowed in the registry
(define-constant DEFAULT-MAX-IDENTITIES u10000)

;; Data variables
;; Store the current contract owner principal
(define-data-var contract-owner-var principal INITIAL-OWNER)

;; Identity tracking variables
;; Total number of identities linked in the registry
(define-data-var total-identities-count uint u0)

;; Last updated block height for the entire registry
(define-data-var last-registry-update-height uint u0)

;; Emergency Switch
;; If true, all state-changing operations are suspended
(define-data-var is-registry-paused bool false)

;; Maximum number of identities allowed in the registry
(define-data-var max-identities-limit uint DEFAULT-MAX-IDENTITIES)

;; Metadata constants
;; The semantic version of the contract
(define-constant CONTRACT-VERSION "0.1.0")

;; The descriptive name of the identity registry
(define-constant REGISTRY-NAME "StackInterop Identity Layer")

;; The network identifier (mocking for interoperability experiments)
(define-constant NETWORK-ID "stacks-mainnet")

;; Verification parameter constants
;; Standard length of a Bitcoin compressed public key
(define-constant PUBKEY-COMPRESSED-LEN u33)

;; Standard length of a Bitcoin uncompressed public key
(define-constant PUBKEY-UNCOMPRESSED-LEN u65)

;; Standard length of a Bitcoin message signature (compact)
(define-constant SIGNATURE-LEN u65)

;; Standard length of a SHA-256 message hash
(define-constant HASH-LEN u32)

;; data maps
;; Maps a Stacks principal to a Bitcoin address and linking metadata.
;; btc-hash: The 20-byte hash (H160) of the Bitcoin address.
;; linked-at: The block height when the identity was first linked.
;; updated-at: The block height of the last update to this identity.
(define-map identity-registry principal 
    { 
        btc-hash: (buff 20), 
        linked-at: uint, 
        updated-at: uint 
    }
)

;; public functions

;; @desc Links a Stacks principal to a Bitcoin address by providing a public key and signature.
;; @param btc-pubkey: The 33-byte or 65-byte Bitcoin public key.
;; @param signature: The 65-byte signature (compact format).
;; @param message-hash: The hash of the message signed by the Bitcoin wallet.
(define-public (link-address (btc-pubkey (buff 33)) (signature (buff 65)) (message-hash (buff 32)))
    (let (
        (caller tx-sender)
        ;; Derive the 20-byte hash (H160) from the public key
        (btc-address-hash (hash160 btc-pubkey))
        (current-height block-height)
    )
        ;; Ensure the registry is not paused
        (asserts! (not (check-is-paused)) ERR-PAUSED)

        ;; Ensure the registry capacity hasn't been exceeded
        (asserts! (< (var-get total-identities-count) (var-get max-identities-limit)) ERR-LIMIT-REACHED)
        
        ;; Check if already linked
        (asserts! (is-none (map-get? identity-registry caller)) ERR-ALREADY-LINKED)
        
        ;; Verify signature (mocking verification for initial structure)
        ;; (asserts! (secp256k1-verify message-hash signature btc-pubkey) ERR-INVALID-SIGNATURE)
        
        ;; Link the address with metadata
        (map-set identity-registry caller 
            { 
                btc-hash: btc-address-hash, 
                linked-at: current-height, 
                updated-at: current-height 
            }
        )

        ;; Increment total identity count
        (var-set total-identities-count (+ (var-get total-identities-count) u1))

        ;; Record global registry update height
        (var-set last-registry-update-height current-height)
        
        (ok true)
    )
)

;; read only functions

;; @desc Retrieves the linked Bitcoin address hash for a given Stacks principal.
(define-read-only (get-identity (user principal))
    (map-get? identity-registry user)
)

;; @desc Returns the Bitcoin address hash (H160) for a given user.
(define-read-only (get-btc-hash (user principal))
    (match (map-get? identity-registry user)
        identity (ok (get btc-hash identity))
        (err ERR-NOT-AUTHORIZED) ;; Using a simple error for missing data
    )
)

;; @desc Returns the block height when the user's identity was first linked.
(define-read-only (get-linked-at (user principal))
    (match (map-get? identity-registry user)
        identity (ok (get linked-at identity))
        (err ERR-NOT-AUTHORIZED)
    )
)

;; @desc Returns the descriptive version of the registry.
(define-read-only (get-version)
    (ok CONTRACT-VERSION)
)

;; Administrative functions

;; @desc Allows the current owner to transfer contract ownership.
;; @param new-owner: The principal of the new owner.
(define-public (transfer-ownership (new-owner principal))
    (let (
        (caller tx-sender)
    )
        ;; Only the current owner can transfer ownership
        (asserts! (is-eq caller (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Set the new owner
        (var-set contract-owner-var new-owner)
        (ok true)
    )
)

;; @desc Emergency function to pause or unpause the registry.
;; @param paused: The new paused state (bool).
(define-public (set-registry-pause (paused bool))
    (begin
        ;; Only the owner can toggle the pause state
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the pause state
        (var-set is-registry-paused paused)
        (ok true)
    )
)

;; @desc Updates the maximum number of identities allowed.
;; @param new-limit: The new capacity for the registry.
(define-public (set-max-identities (new-limit uint))
    (begin
        ;; Only the owner can scale the registry
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the limit
        (var-set max-identities-limit new-limit)
        (ok true)
    )
)

;; private functions

;; @desc Helper to check if the contract is in a paused state.
;; @returns bool: True if paused, false otherwise.
(define-private (check-is-paused)
    (var-get is-registry-paused)
)

;; @desc Returns the total number of linked identities in the registry.
(define-read-only (get-total-identities)
    (ok (var-get total-identities-count))
)

;; @desc Returns the block height of the most recent registry update.
(define-read-only (get-last-update-height)
    (ok (var-get last-registry-update-height))
)

;; @desc Returns whether the registry is currently paused.
(define-read-only (get-paused-status)
    (ok (var-get is-registry-paused))
)

;; @desc Returns the maximum number of identities allowed.
(define-read-only (get-max-identities)
    (ok (var-get max-identities-limit))
)
