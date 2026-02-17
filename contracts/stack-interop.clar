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

;; Reputation constants
;; Initial reputation score given to newly linked identities
(define-constant DEFAULT-REPUTATION-SCORE u10)

;; Timing constants
;; Number of blocks to wait before a user can re-verify or update their identity
(define-constant DEFAULT-VERIFICATION-COOLDOWN u144) ;; ~24 hours on Bitcoin timing

;; Error code u108: Operation requested too soon after the last linking
(define-constant ERR-COOLDOWN-ACTIVE (err u1008))

;; Tier constants
(define-constant TIER-0 u0) ;; Unverified or Basic
(define-constant TIER-1 u1) ;; Verified Bitcoin Link
(define-constant TIER-2 u2) ;; High Reputation / Premium

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

;; Cooldown period for identity operations (in blocks)
(define-data-var verification-cooldown-limit uint DEFAULT-VERIFICATION-COOLDOWN)

;; Whether the verification window is currently open for specific tiers
(define-data-var verification-window-open bool true)

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

;; Maps a Stacks principal to their current identity verification tier.
;; tier: The numeric level of verification (0, 1, 2, etc.).
(define-map identity-tiers principal 
    { 
        tier: uint, 
        granted-at: uint 
    }
)

;; Maps an index to administrative actions for auditing purposes.
;; action: A descriptive string of the action taken.
;; caller: The principal who performed the action.
;; height: The block height of the action.
(define-map admin-audit-log uint 
    { 
        action: (string-ascii 64), 
        caller: principal, 
        height: uint 
    }
)

;; Counter for audit log entries
(define-data-var audit-log-index uint u0)

;; Maps a Stacks principal to their calculated reputation score.
;; The score is used to determine privileges in the ecosystem.
(define-map identity-reputation principal 
    { 
        score: uint, 
        last-updated: uint 
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

        ;; Initialize reputation score for the new identity
        (map-set identity-reputation caller 
            { 
                score: DEFAULT-REPUTATION-SCORE, 
                last-updated: current-height 
            }
        )

        ;; Initialize identity tier to Tier 1 upon successful linking
        (map-set identity-tiers caller 
            { 
                tier: TIER-1, 
                granted-at: current-height 
            }
        )
        
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
        
        ;; Record the action in the audit log
        (log-admin-action "Transfer Ownership")
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

        ;; Record the action in the audit log
        (log-admin-action "Toggle Registry Pause")
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

        ;; Record the action in the audit log
        (log-admin-action "Update Max Identities Limit")
        (ok true)
    )
)

;; @desc Updates the verification cooldown period.
;; @param new-cooldown: The new cooldown in blocks.
(define-public (set-verification-cooldown (new-cooldown uint))
    (begin
        ;; Only the owner can adjust timing parameters
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the cooldown
        (var-set verification-cooldown-limit new-cooldown)

        ;; Record the action in the audit log
        (log-admin-action "Update Verification Cooldown")
        (ok true)
    )
)

;; @desc Toggles the verification window status.
;; @param status: The new window status (bool).
(define-public (set-verification-window-status (status bool))
    (begin
        ;; Only the owner can control verification windows
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the status
        (var-set verification-window-open status)
        (ok true)
    )
)

;; @desc Updates the reputation score for a specific user.
;; @param user: The principal of the user.
;; @param new-score: The new reputation score.
(define-public (update-reputation (user principal) (new-score uint))
    (begin
        ;; Only the owner can manually adjust reputation
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the mapping
        (map-set identity-reputation user 
            { 
                score: new-score, 
                last-updated: block-height 
            }
        )

        ;; Record the action in the audit log
        (log-admin-action "Update User Reputation")
        (ok true)
    )
)

;; @desc Upgrades or modifies the verification tier for a specific user.
;; @param user: The principal of the user.
;; @param new-tier: The new tier level.
(define-public (set-tier (user principal) (new-tier uint))
    (begin
        ;; Only the owner can manually set tiers
        (asserts! (is-eq tx-sender (var-get contract-owner-var)) ERR-NOT-OWNER)
        
        ;; Update the tier mapping
        (map-set identity-tiers user 
            { 
                tier: new-tier, 
                granted-at: block-height 
            }
        )
        (ok true)
    )
)

;; private functions

;; @desc Checks if the user is still within their verification cooldown period.
;; @param user: The principal to check.
(define-private (check-cooldown (user principal))
    (match (map-get? identity-registry user)
        identity (>= block-height (+ (get updated-at identity) (var-get verification-cooldown-limit)))
        true ;; If no identity exists, cooldown is not applicable
    )
)

;; @desc Helper to check if the contract is in a paused state.
;; @returns bool: True if paused, false otherwise.
(define-private (check-is-paused)
    (var-get is-registry-paused)
)

;; @desc Records an administrative action to the audit log.
;; @param action: Descriptive text of the action.
(define-private (log-admin-action (action (string-ascii 64)))
    (let (
        (current-index (var-get audit-log-index))
    )
        (map-set admin-audit-log current-index 
            { 
                action: action, 
                caller: tx-sender, 
                height: block-height 
            }
        )
        (var-set audit-log-index (+ current-index u1))
        true
    )
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

;; @desc Returns the current verification cooldown period.
(define-read-only (get-verification-cooldown)
    (ok (var-get verification-cooldown-limit))
)

;; @desc Returns the status of the verification window.
(define-read-only (get-verification-window-status)
    (ok (var-get verification-window-open))
)

;; @desc Returns the reputation score and last update for a given user.
(define-read-only (get-reputation (user principal))
    (map-get? identity-reputation user)
)

;; @desc Returns the current verification tier for a given user.
(define-read-only (get-user-tier (user principal))
    (map-get? identity-tiers user)
)
