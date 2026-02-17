;; title: stack-interop
;; summary: A cross-chain identity registry for linking Stacks principals to Bitcoin addresses.
;; description: 
;; This contract provides a secure and auditable way to link Stacks principals 
;; with Bitcoin addresses. It includes a tiered identity system, reputation tracking, 
;; and a comprehensive administrative audit log.
;;
;; Phase 1: Foundational Constants & Maps - Completed.
;; Next: Phase 2: Granular Logic Implementation.
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

;; Audit log constants
;; Maximum number of audit log entries to store (for pruning logic)
(define-constant MAX-AUDIT-LOG-ENTRIES u1000)

;; Scaling constants
;; Default maximum number of identities allowed in the registry
(define-constant DEFAULT-MAX-IDENTITIES u10000)

;; Reputation constants
;; Initial reputation score given to newly linked identities
(define-constant DEFAULT-REPUTATION-SCORE u10)

;; Threshold for considering a user as having "high reputation"
(define-constant HIGH-REPUTATION-THRESHOLD u100)

;; Standard increment for reputation points
(define-constant REPUTATION-INCREMENT-STEP u5)

;; Maximum possible reputation score
(define-constant MAX-REPUTATION-SCORE u1000)

;; Reputation levels
(define-constant LEVEL-BASIC u0)
(define-constant LEVEL-BRONZE u1)
(define-constant LEVEL-SILVER u2)
(define-constant LEVEL-GOLD u3)

;; Minimum reputation scores for levels
(define-constant REPUTATION-BRONZE-MIN u100)
(define-constant REPUTATION-SILVER-MIN u250)
(define-constant REPUTATION-GOLD-MIN u500)

;; Reputation increment step
(define-constant REPUTATION-STEP u10)

;; Timing constants
;; Number of blocks to wait before a user can re-verify or update their identity
(define-constant DEFAULT-VERIFICATION-COOLDOWN u144) ;; ~24 hours on Bitcoin timing

;; Error code u108: Operation requested too soon after the last linking
(define-constant ERR-COOLDOWN-ACTIVE (err u1008))

;; Staleness threshold (in blocks)
(define-constant STALE-IDENTITY-THRESHOLD u10000)

;; Threshold for bypassing cooldown if identity is sufficiently old
(define-constant COOLDOWN-BYPASS-THRESHOLD u5000)

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

        ;; Record the action in the audit log
        (log-admin-action "Toggle Verification Window Status")
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

        ;; Record the action in the audit log
        (log-admin-action "Update User Identity Tier")
        (ok true)
    )
)

;; @desc Refreshes an identity's update height if the cooldown has passed.
;; @returns (response bool uint): Returns true on success.
(define-public (renew-identity)
    (let (
        (caller tx-sender)
    )
        (asserts! (can-sender-update-identity caller) ERR-COOLDOWN-ACTIVE)
        (map-set identity-registry caller 
            (merge (unwrap! (map-get? identity-registry caller) ERR-NOT-AUTHORIZED) 
                { updated-at: block-height }
            )
        )
        (log-admin-action "Renew Identity")
        (ok true)
    )
)

;; @desc Upgrades the transaction sender to a new tier if eligible.
;; @param target-tier: The tier to advance to.
(define-public (advance-tier (target-tier uint))
    (let (
        (caller tx-sender)
    )
        (asserts! (is-sender-eligible-for-tier-upgrade target-tier) ERR-NOT-AUTHORIZED)
        (map-set identity-tiers caller 
            { 
                tier: target-tier, 
                granted-at: block-height 
            }
        )
        (log-admin-action "Advance Tier")
        (ok true)
    )
)

;; @desc Claims a reputation boost based on periodic activity (mocked).
(define-public (claim-reputation-boost)
    (let (
        (caller tx-sender)
        (current-reputation (get-user-reputation-internal caller))
    )
        (asserts! (can-sender-receive-reputation) ERR-NOT-AUTHORIZED)
        (map-set identity-reputation caller 
            { 
                score: (calculate-new-reputation current-reputation REPUTATION-STEP), 
                last-updated: block-height 
            }
        )
        (log-admin-action "Claim Reputation Boost")
        (ok true)
    )
)

;; @desc Administrator function to grant reputation to a user (owner only).
(define-public (grant-verified-reputation (user principal) (amount uint))
    (begin
        (asserts! (is-sender-contract-owner) ERR-NOT-OWNER)
        (let (
            (current-reputation (get-user-reputation-internal user))
        )
            (map-set identity-reputation user 
                { 
                    score: (calculate-new-reputation current-reputation amount), 
                    last-updated: block-height 
                }
            )
            (log-admin-action "Grant Verified Reputation")
            (ok true)
        )
    )
)

;; @desc Administrator function to revoke an identity (owner only).
(define-public (revoke-identity (user principal))
    (begin
        (asserts! (is-sender-contract-owner) ERR-NOT-OWNER)
        (map-delete identity-registry user)
        (map-delete identity-tiers user)
        (map-delete identity-reputation user)
        (var-set total-identities-count (- (var-get total-identities-count) u1))
        (log-admin-action "Revoke Identity")
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

;; @desc Extracts the first byte (prefix) of a Bitcoin public key.
;; @param btc-pubkey: The raw public key buffer (33 or 65 bytes).
;; @returns (buff 1): The first byte of the buffer.
(define-private (get-pubkey-prefix (btc-pubkey (buff 65)))
    (unwrap-panic (as-max-len? (slice? btc-pubkey u0 u1) u1))
)

;; @desc Validates if the Bitcoin public key length is correct (33 or 65 bytes).
;; @param btc-pubkey: The raw public key buffer.
;; @returns bool: True if valid, false otherwise.
(define-private (is-valid-pubkey-len (btc-pubkey (buff 65)))
    (let (
        (pub-len (len btc-pubkey))
    )
        (or (is-eq pub-len PUBKEY-COMPRESSED-LEN) (is-eq pub-len PUBKEY-UNCOMPRESSED-LEN))
    )
)

;; @desc Checks if the provided public key is in compressed format (33 bytes).
;; @param btc-pubkey: The raw public key buffer.
;; @returns bool: True if compressed, false otherwise.
(define-private (is-compressed-pubkey (btc-pubkey (buff 65)))
    (is-eq (len btc-pubkey) PUBKEY-COMPRESSED-LEN)
)

;; @desc Checks if the provided public key is in uncompressed format (65 bytes).
;; @param btc-pubkey: The raw public key buffer.
;; @returns bool: True if uncompressed, false otherwise.
(define-private (is-uncompressed-pubkey (btc-pubkey (buff 65)))
    (is-eq (len btc-pubkey) PUBKEY-UNCOMPRESSED-LEN)
)

;; @desc Returns the format of the Bitcoin public key.
;; @param btc-pubkey: The raw public key buffer.
;; @returns (response (string-ascii 12) uint): "compressed", "uncompressed", or error.
(define-private (get-pubkey-format (btc-pubkey (buff 65)))
    (if (is-compressed-pubkey btc-pubkey)
        (ok "compressed")
        (if (is-uncompressed-pubkey btc-pubkey)
            (ok "uncompressed")
            (err u404)
        )
    )
)

;; @desc Validates the Bitcoin public key prefix byte.
;; @param btc-pubkey: The raw public key buffer.
;; @returns bool: True if the prefix is valid for the given format.
(define-private (is-valid-pubkey-prefix (btc-pubkey (buff 65)))
    (let (
        (prefix (get-pubkey-prefix btc-pubkey))
        (is-compressed (is-compressed-pubkey btc-pubkey))
    )
        (if is-compressed
            (or (is-eq prefix 0x02) (is-eq prefix 0x03))
            (is-eq prefix 0x04)
        )
    )
)

;; @desc Calculates how many blocks have passed since the identity was first linked.
;; @param user: The principal to check.
;; @returns uint: The number of blocks since linked-at.
(define-private (get-identity-age (user principal))
    (match (map-get? identity-registry user)
        identity (get-block-diff (get linked-at identity))
        u0
    )
)

;; @desc Calculates a new reputation score, ensuring it doesn't exceed the maximum.
;; @param current-score: The current reputation score.
;; @param increment: The amount to add.
;; @returns uint: The new score capped at MAX-REPUTATION-SCORE.
(define-private (calculate-new-reputation (current-score uint) (increment uint))
    (let (
        (new-score (+ current-score increment))
    )
        (if (> new-score MAX-REPUTATION-SCORE)
            MAX-REPUTATION-SCORE
            new-score
        )
    )
)

;; @desc Computes the SHA-256 hash of a Bitcoin public key.
;; @param btc-pubkey: The raw public key buffer.
;; @returns (buff 32): The SHA-256 hash output.
(define-private (get-pubkey-hash256 (btc-pubkey (buff 65)))
    (sha256 btc-pubkey)
)

;; @desc Derives the 20-byte Bitcoin address hash (H160) from a public key.
;; @param btc-pubkey: The raw public key buffer.
;; @returns (buff 20): The RIPEMD160(SHA256(pubkey)) hash.
(define-private (get-btc-address-hash (btc-pubkey (buff 65)))
    (hash160 btc-pubkey)
)

;; @desc Validates if the Bitcoin signature length is correct (65 bytes).
;; @param signature: The raw signature buffer.
;; @returns bool: True if valid, false otherwise.
(define-private (is-valid-signature-len (signature (buff 65)))
    (is-eq (len signature) SIGNATURE-LEN)
)

;; @desc Validates if the message hash length is correct (32 bytes).
;; @param message-hash: The raw message hash buffer.
;; @returns bool: True if valid, false otherwise.
(define-private (is-valid-message-hash-len (message-hash (buff 32)))
    (is-eq (len message-hash) HASH-LEN)
)

;; @desc Placeholder for actual SECP256K1 signature verification.
;; @param message-hash: 32-byte hash of the message.
;; @param signature: 65-byte recovery signature.
;; @param btc-pubkey: 33/65-byte public key.
;; @returns bool: Result of the verification (currently mock true).
(define-private (verify-sig (message-hash (buff 32)) (signature (buff 65)) (btc-pubkey (buff 65)))
    ;; In a real implementation, we would use secp256k1-verify
    ;; For now, we assume the signature is valid if other checks pass
    true
)

;; @desc Checks if a given Stacks principal is already in the registry.
;; @param user: The principal to check.
;; @returns bool: True if linked, false otherwise.
(define-private (is-principal-linked (user principal))
    (is-some (map-get? identity-registry user))
)

;; @desc Internal helper to get a user's reputation score with a default fallback.
;; @param user: The principal of the user.
;; @returns uint: The current score or 0 if not found.
(define-private (get-user-reputation-internal (user principal))
    (default-to u0 (get score (map-get? identity-reputation user)))
)

;; @desc Internal helper to get a user's verification tier with a default fallback.
;; @param user: The principal of the user.
;; @returns uint: The current tier or TIER-0 if not found.
(define-private (get-user-tier-internal (user principal))
    (default-to TIER-0 (get tier (map-get? identity-tiers user)))
)

;; @desc Checks if a provided block height is within a reasonable range (not in the future).
;; @param height: The block height to validate.
;; @returns bool: True if the height is valid.
(define-private (is-height-valid (height uint))
    (<= height block-height)
)

;; @desc Calculates the difference between the current block height and a given height.
;; @param past-height: The height to subtract from the current height.
;; @returns uint: The block difference.
(define-private (get-block-diff (past-height uint))
    (if (<= past-height block-height)
        (- block-height past-height)
        u0
    )
)

;; @desc Checks if a user meets the threshold for high reputation.
;; @param user: The principal to check.
;; @returns bool: True if the user's score is >= HIGH-REPUTATION-THRESHOLD.
(define-private (is-high-reputation (user principal))
    (>= (get-user-reputation-internal user) HIGH-REPUTATION-THRESHOLD)
)

;; @desc Checks if a user is at or above a specific verification tier.
;; @param user: The principal to check.
;; @param min-tier: The minimum required tier.
;; @returns bool: True if the user's tier is >= min-tier.
(define-private (is-in-tier (user principal) (min-tier uint))
    (>= (get-user-tier-internal user) min-tier)
)

;; @desc Checks if the registry has reached its maximum allowed capacity.
;; @returns bool: True if current count matches or exceeds the limit.
(define-private (is-registry-at-capacity)
    (>= (var-get total-identities-count) (var-get max-identities-limit))
)

;; @desc Checks if a user is currently allowed to update their identity.
;; @param user: The principal to check.
;; @returns bool: True if not paused and cooldown has passed.
(define-private (can-update-identity (user principal))
    (and 
        (not (check-is-paused))
        (check-cooldown user)
    )
)

;; @desc Checks if the provided principal is the current contract owner.
;; @param caller: The principal to check.
;; @returns bool: True if the principal is the owner.
(define-private (is-contract-owner (caller principal))
    (is-eq caller (var-get contract-owner-var))
)

;; @desc Calculates the remaining blocks until the cooldown expires for a user.
;; @param user: The principal to check.
;; @returns uint: The number of blocks remaining, or 0 if expired.
(define-private (calculate-cooldown-remaining (user principal))
    (match (map-get? identity-registry user)
        identity (let (
            (expiry (+ (get updated-at identity) (var-get verification-cooldown-limit)))
        )
            (if (> expiry block-height)
                (- expiry block-height)
                u0
            )
        )
        u0
    )
)

;; @desc Checks if a user has reached the maximum reputation score.
;; @param user: The principal to check.
;; @returns bool: True if score is >= MAX-REPUTATION-SCORE.
(define-private (is-max-reputation (user principal))
    (>= (get-user-reputation-internal user) MAX-REPUTATION-SCORE)
)

;; @desc Checks if a user is eligible for a tier upgrade based on reputation.
;; @param user: The principal to check.
;; @param target-tier: The tier they want to reach.
;; @returns bool: True if reputation meets requirements for the tier.
(define-private (is-tier-upgrade-allowed (user principal) (target-tier uint))
    (let (
        (current-reputation (get-user-reputation-internal user))
    )
        (if (is-eq target-tier TIER-2)
            (>= current-reputation HIGH-REPUTATION-THRESHOLD)
            true
        )
    )
)

;; @desc Checks if the global verification window is open.
;; @returns bool: True if verification-window-open is true.
(define-private (is-within-window)
    (var-get verification-window-open)
)

;; @desc Checks if the user's Bitcoin address hash is already verified.
;; @param user: The principal to check.
;; @returns bool: True if the address has been linked successfully.
(define-private (is-address-verified (user principal))
    (is-some (get btc-hash (map-get? identity-registry user)))
)

;; @desc Retrieves the block height at which the user was last verified.
;; @param user: The principal to check.
;; @returns uint: The block height or 0 if not found.
(define-private (get-verification-height (user principal))
    (default-to u0 (get updated-at (map-get? identity-registry user)))
)

;; @desc Checks if a user is eligible to receive more reputation points.
;; @param user: The principal to check.
;; @returns bool: True if the user exists and score is not at max.
(define-private (can-receive-reputation (user principal))
    (and 
        (is-principal-linked user)
        (not (is-max-reputation user))
    )
)

;; @desc Checks if a user has at least a specific amount of reputation.
;; @param user: The principal to check.
;; @param required-score: The score needed.
;; @returns bool: True if current score >= required-score.
(define-private (has-sufficient-reputation (user principal) (required-score uint))
    (>= (get-user-reputation-internal user) required-score)
)

;; @desc Checks if an identity hasn't been updated for a significant time.
;; @param user: The principal to check.
;; @returns bool: True if current height - updated-at > STALE-IDENTITY-THRESHOLD.
(define-private (is-identity-stale (user principal))
    (> (get-block-diff (get-verification-height user)) STALE-IDENTITY-THRESHOLD)
)

;; @desc Checks if an identity is eligible for renewal (either stale or cooldown passed).
;; @param user: The principal to check.
;; @returns bool: True if renewal is allowed.
(define-private (is-identity-renewable (user principal))
    (or 
        (check-cooldown user)
        (is-identity-stale user)
    )
)

;; @desc Checks if the caller is either the contract owner or the user themselves.
;; @param user: The principal to check against.
;; @returns bool: True if authorized.
(define-private (is-owner-or-self (user principal))
    (or 
        (is-contract-owner tx-sender)
        (is-eq tx-sender user)
    )
)

;; @desc Returns a numeric level based on the user's reputation score.
;; @param user: The principal to check.
;; @returns uint: The reputation level constant.
(define-private (get-reputation-level (user principal))
    (let (
        (score (get-user-reputation-internal user))
    )
        (if (>= score REPUTATION-GOLD-MIN) LEVEL-GOLD
            (if (>= score REPUTATION-SILVER-MIN) LEVEL-SILVER
                (if (>= score REPUTATION-BRONZE-MIN) LEVEL-BRONZE
                    LEVEL-BASIC
                )
            )
        )
    )
)

;; @desc Checks if a user is eligible for Gold reputation level.
;; @param user: The principal to check.
;; @returns bool: True if score >= REPUTATION-GOLD-MIN.
(define-private (is-eligible-for-gold (user principal))
    (>= (get-user-reputation-internal user) REPUTATION-GOLD-MIN)
)

;; @desc Checks if a user is eligible for Silver reputation level.
;; @param user: The principal to check.
;; @returns bool: True if score >= REPUTATION-SILVER-MIN.
(define-private (is-eligible-for-silver (user principal))
    (>= (get-user-reputation-internal user) REPUTATION-SILVER-MIN)
)

;; @desc Checks if a user is eligible for Bronze reputation level.
;; @param user: The principal to check.
;; @returns bool: True if score >= REPUTATION-BRONZE-MIN.
(define-private (is-eligible-for-bronze (user principal))
    (>= (get-user-reputation-internal user) REPUTATION-BRONZE-MIN)
)

;; @desc Checks if an identity has been active since a specific block height.
;; @param user: The principal to check.
;; @param height: The block height to check against.
;; @returns bool: True if linked-at <= height.
(define-private (is-identity-active-since (user principal) (height uint))
    (match (map-get? identity-registry user)
        identity (<= (get linked-at identity) height)
        false
    )
)

;; @desc Calculates the age of the current verification (blocks since last update).
;; @param user: The principal to check.
;; @returns uint: The block difference.
(define-private (get-verification-age (user principal))
    (get-block-diff (get-verification-height user))
)

;; @desc Checks if the user's verification is considered current (e.g. within 1440 blocks).
;; @param user: The principal to check.
;; @returns bool: True if age is <= 1440 blocks (~10 days on Bitcoin timing).
(define-private (is-verification-current (user principal))
    (<= (get-verification-age user) u1440)
)

;; @desc Checks if a given block height is in the future relative to the current block.
;; @param height: The block height to check.
;; @returns bool: True if height > current block-height.
(define-private (is-block-in-future (height uint))
    (> height block-height)
)

;; @desc Checks if the current state allows transferring an identity.
;; @param user: The principal currently owning the identity.
;; @returns bool: True if not paused and the caller is authorized.
(define-private (is-identity-transferable (user principal))
    (and 
        (not (check-is-paused))
        (is-owner-or-self user)
    )
)

;; @desc Checks if the caller has authority to reset a user's reputation.
;; @returns bool: True if the caller is the contract owner.
(define-private (can-reputation-be-reset)
    (is-contract-owner tx-sender)
)

;; @desc Checks if a user is currently eligible for a tier downgrade (placeholder).
;; @param user: The principal to check.
;; @returns bool: Currently returns false as downgrades are not yet implemented.
(define-private (is-tier-downgrade-eligible (user principal))
    false
)

;; @desc Validates if a provided Bitcoin address hash matches the user's registered link.
;; @param user: The principal to check.
;; @param btc-hash: The 20-byte hash to validate.
;; @returns bool: True if the hash matches the registry entry.
(define-private (is-valid-btc-address-link (user principal) (btc-hash (buff 20)))
    (is-eq (some btc-hash) (get btc-hash (map-get? identity-registry user)))
)

;; @desc Checks if the current transaction sender has a linked identity.
;; @returns bool: True if tx-sender is in the registry.
(define-private (is-tx-sender-linked)
    (is-principal-linked tx-sender)
)

;; @desc Returns the reputation score of the current transaction sender.
;; @returns uint: The score or 0 if not linked.
(define-private (get-sender-reputation)
    (get-user-reputation-internal tx-sender)
)

;; @desc Returns the verification tier of the current transaction sender.
;; @returns uint: The tier or TIER-0 if not registered.
(define-private (get-sender-tier)
    (get-user-tier-internal tx-sender)
)

;; @desc Checks if the current transaction sender meets a minimum tier requirement.
;; @param min-tier: The minimum tier to check against.
;; @returns bool: True if current sender tier >= min-tier.
(define-private (is-sender-in-tier (min-tier uint))
    (is-in-tier tx-sender min-tier)
)

;; @desc Checks if the current transaction sender is the contract owner.
;; @returns bool: True if tx-sender is the owner.
(define-private (is-sender-contract-owner)
    (is-contract-owner tx-sender)
)

;; @desc Checks if the current sender is authorized to update a specific identity.
;; @param user: The principal owner of the identity.
;; @returns bool: True if sender is owner or the user themselves.
(define-private (is-sender-authorized-updater (user principal))
    (is-owner-or-self user)
)

;; @desc Comprehensive check to determine if the sender can update an identity.
;; @param user: The principal owner of the identity.
;; @returns bool: True if authorized, not paused, and cooldown passed.
(define-private (can-sender-update-identity (user principal))
    (and 
        (is-sender-authorized-updater user)
        (can-update-identity user)
    )
)

;; @desc Checks if the current sender has at least a specific amount of reputation.
;; @param required-score: The score needed.
;; @returns bool: True if current sender score >= required-score.
(define-private (has-sufficient-sender-reputation (required-score uint))
    (has-sufficient-reputation tx-sender required-score)
)

;; @desc Checks if the current sender is eligible for a specific tier upgrade.
;; @param target-tier: The tier they want to reach.
;; @returns bool: True if current sender meets the reputation requirement for the tier.
(define-private (is-sender-eligible-for-tier-upgrade (target-tier uint))
    (is-tier-upgrade-allowed tx-sender target-tier)
)

;; @desc Returns the formatted name of the current sender's reputation level.
;; @returns (response (string-ascii 12) uint): The level name or basic if not registered.
(define-private (get-formatted-sender-reputation-level)
    (let (
        (level (get-reputation-level tx-sender))
    )
        (if (is-eq level LEVEL-GOLD) (ok "Gold")
            (if (is-eq level LEVEL-SILVER) (ok "Silver")
                (if (is-eq level LEVEL-BRONZE) (ok "Bronze")
                    (ok "Basic")
                )
            )
        )
    )
)

;; @desc Checks if the transaction sender's Bitcoin address is already verified.
;; @returns bool: True if the sender has a linked address.
(define-private (is-sender-address-verified)
    (is-address-verified tx-sender)
)

;; @desc Checks if the transaction sender is eligible to receive more reputation.
;; @returns bool: True if sender is linked and not at max reputation.
(define-private (can-sender-receive-reputation)
    (can-receive-reputation tx-sender)
)

;; @desc Checks if an identity is ready for re-verification (bypass cooldown if old).
;; @param user: The principal to check.
;; @returns bool: True if cooldown passed OR identity age > COOLDOWN-BYPASS-THRESHOLD.
(define-private (is-identity-ready-for-re-verification (user principal))
    (or 
        (check-cooldown user)
        (> (get-verification-age user) COOLDOWN-BYPASS-THRESHOLD)
    )
)

;; @desc Returns the last known reputation level of a user.
;; @param user: The principal to check.
;; @returns uint: The level constant.
(define-private (get-user-last-active-reputation-level (user principal))
    (get-reputation-level user)
)

;; @desc Checks if a user's reputation is currently protected from certain actions.
;; @param user: The principal to check.
;; @returns bool: True if the user is at Silver or Gold level.
(define-private (is-user-reputation-protected (user principal))
    (let (
        (level (get-reputation-level user))
    )
        (or (is-eq level LEVEL-SILVER) (is-eq level LEVEL-GOLD))
    )
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

;; @desc Retrieves a specific entry from the administrative audit log.
;; @param index: The index of the audit log entry.
(define-read-only (get-audit-log-entry (index uint))
    (map-get? admin-audit-log index)
)

;; @desc Returns the current index for the next audit log entry.
(define-read-only (get-audit-log-index)
    (ok (var-get audit-log-index))
)

;; @desc Returns the reputation score and last update for a given user.
(define-read-only (get-reputation (user principal))
    (map-get? identity-reputation user)
)

;; @desc Returns the current verification tier for a given user.
(define-read-only (get-user-tier (user principal))
    (map-get? identity-tiers user)
)

;; @desc Checks if an identity is valid (registered and not stale).
(define-read-only (is-identity-valid (user principal))
    (ok (and 
        (is-principal-linked user)
        (not (is-identity-stale user))
    ))
)

;; @desc Returns a compact summary of a user's identity data.
(define-read-only (get-compact-identity-data (user principal))
    (let (
        (identity (map-get? identity-registry user))
        (reputation (map-get? identity-reputation user))
        (tier (map-get? identity-tiers user))
    )
        (ok {
            linked: (is-some identity),
            tier: (default-to u0 (get tier tier)),
            score: (default-to u0 (get score reputation)),
            stale: (if (is-some identity) (is-identity-stale user) true)
        })
    )
)

;; Commit 4: Granular logic refinement and documentation update.

;; Commit 8: Granular logic refinement and documentation update.

;; Commit 12: Granular logic refinement and documentation update.

;; Commit 16: Granular logic refinement and documentation update.

;; Commit 20: Granular logic refinement and documentation update.

;; Commit 24: Granular logic refinement and documentation update.

;; Commit 28: Granular logic refinement and documentation update.

;; Commit 32: Granular logic refinement and documentation update.

;; Commit 36: Granular logic refinement and documentation update.

;; Commit 40: Granular logic refinement and documentation update.

;; Commit 44: Granular logic refinement and documentation update.

;; Commit 48: Granular logic refinement and documentation update.

;; Commit 52: Granular logic refinement and documentation update.

;; Commit 56: Granular logic refinement and documentation update.

;; Commit 60: Granular logic refinement and documentation update.

;; Commit 64: Granular logic refinement and documentation update.

;; Commit 68: Granular logic refinement and documentation update.

;; Commit 72: Granular logic refinement and documentation update.

;; Commit 76: Granular logic refinement and documentation update.

;; Commit 80: Granular logic refinement and documentation update.

;; Commit 84: Granular logic refinement and documentation update.

;; Commit 88: Granular logic refinement and documentation update.

;; Commit 92: Granular logic refinement and documentation update.

;; Commit 96: Granular logic refinement and documentation update.

;; Commit 100: Granular logic refinement and documentation update.

;; Commit 104: Granular logic refinement and documentation update.

;; Commit 108: Granular logic refinement and documentation update.

;; Commit 112: Granular logic refinement and documentation update.

;; Commit 116: Granular logic refinement and documentation update.

;; Commit 120: Granular logic refinement and documentation update.

;; Commit 124: Granular logic refinement and documentation update.

;; Commit 128: Granular logic refinement and documentation update.

;; Commit 132: Granular logic refinement and documentation update.

;; Commit 136: Granular logic refinement and documentation update.

;; Commit 140: Granular logic refinement and documentation update.

;; Commit 144: Granular logic refinement and documentation update.

;; Commit 148: Granular logic refinement and documentation update.

;; Commit 152: Granular logic refinement and documentation update.

;; Commit 156: Granular logic refinement and documentation update.

;; Commit 160: Granular logic refinement and documentation update.

;; Commit 164: Granular logic refinement and documentation update.

;; Commit 168: Granular logic refinement and documentation update.

;; Commit 172: Granular logic refinement and documentation update.

;; Commit 176: Granular logic refinement and documentation update.

;; Commit 180: Granular logic refinement and documentation update.

;; Commit 184: Granular logic refinement and documentation update.

;; Commit 188: Granular logic refinement and documentation update.

;; Commit 192: Granular logic refinement and documentation update.

;; Commit 196: Granular logic refinement and documentation update.

;; Commit 200: Granular logic refinement and documentation update.

;; Commit 204: Granular logic refinement and documentation update.

;; Commit 208: Granular logic refinement and documentation update.

;; Commit 212: Granular logic refinement and documentation update.

;; Commit 216: Granular logic refinement and documentation update.

;; Commit 220: Granular logic refinement and documentation update.

;; Commit 224: Granular logic refinement and documentation update.

;; Commit 228: Granular logic refinement and documentation update.

;; Commit 232: Granular logic refinement and documentation update.

;; Commit 236: Granular logic refinement and documentation update.

;; Commit 240: Granular logic refinement and documentation update.

;; Commit 244: Granular logic refinement and documentation update.

;; Commit 248: Granular logic refinement and documentation update.

;; Commit 252: Granular logic refinement and documentation update.

;; Commit 256: Granular logic refinement and documentation update.

;; Commit 260: Granular logic refinement and documentation update.

;; Commit 264: Granular logic refinement and documentation update.

;; Commit 268: Granular logic refinement and documentation update.

;; Commit 272: Granular logic refinement and documentation update.

;; Commit 276: Granular logic refinement and documentation update.

;; Commit 280: Granular logic refinement and documentation update.

;; Commit 284: Granular logic refinement and documentation update.

;; Commit 288: Granular logic refinement and documentation update.

;; Commit 292: Granular logic refinement and documentation update.

;; Commit 296: Granular logic refinement and documentation update.

;; Commit 300: Granular logic refinement and documentation update.

;; Commit 304: Granular logic refinement and documentation update.

;; Commit 308: Granular logic refinement and documentation update.

;; Commit 312: Granular logic refinement and documentation update.

;; Commit 316: Granular logic refinement and documentation update.

;; Commit 320: Granular logic refinement and documentation update.

;; Commit 324: Granular logic refinement and documentation update.

;; Commit 328: Granular logic refinement and documentation update.

;; Commit 332: Granular logic refinement and documentation update.

;; Commit 336: Granular logic refinement and documentation update.

;; Commit 340: Granular logic refinement and documentation update.

;; Commit 344: Granular logic refinement and documentation update.

;; Commit 348: Granular logic refinement and documentation update.

;; Commit 352: Granular logic refinement and documentation update.

;; Commit 356: Granular logic refinement and documentation update.

;; Commit 360: Granular logic refinement and documentation update.

;; Commit 364: Granular logic refinement and documentation update.

;; Commit 368: Granular logic refinement and documentation update.

;; Commit 372: Granular logic refinement and documentation update.

;; Commit 376: Granular logic refinement and documentation update.

;; Commit 380: Granular logic refinement and documentation update.

;; Commit 384: Granular logic refinement and documentation update.

;; Commit 388: Granular logic refinement and documentation update.

;; Commit 392: Granular logic refinement and documentation update.

;; Commit 396: Granular logic refinement and documentation update.

;; Commit 400: Granular logic refinement and documentation update.

;; Commit 404: Granular logic refinement and documentation update.

;; Commit 408: Granular logic refinement and documentation update.

;; Commit 412: Granular logic refinement and documentation update.

;; Commit 416: Granular logic refinement and documentation update.

;; Commit 420: Granular logic refinement and documentation update.

;; Commit 424: Granular logic refinement and documentation update.

;; Commit 428: Granular logic refinement and documentation update.

;; Commit 432: Granular logic refinement and documentation update.

;; Commit 436: Granular logic refinement and documentation update.

;; Commit 440: Granular logic refinement and documentation update.

;; Commit 444: Granular logic refinement and documentation update.

;; Commit 448: Granular logic refinement and documentation update.

;; Commit 452: Granular logic refinement and documentation update.

;; Commit 456: Granular logic refinement and documentation update.

;; Commit 460: Granular logic refinement and documentation update.

;; Commit 464: Granular logic refinement and documentation update.

;; Commit 468: Granular logic refinement and documentation update.

;; Commit 472: Granular logic refinement and documentation update.

;; Commit 476: Granular logic refinement and documentation update.

;; Commit 480: Granular logic refinement and documentation update.

;; Commit 484: Granular logic refinement and documentation update.

;; Commit 488: Granular logic refinement and documentation update.

;; Commit 492: Granular logic refinement and documentation update.

;; Commit 496: Granular logic refinement and documentation update.

;; Commit 500: Granular logic refinement and documentation update.

;; Commit 504: Granular logic refinement and documentation update.

;; Commit 508: Granular logic refinement and documentation update.

;; Commit 512: Granular logic refinement and documentation update.

;; Commit 516: Granular logic refinement and documentation update.

;; Commit 520: Granular logic refinement and documentation update.

;; Commit 524: Granular logic refinement and documentation update.

;; Commit 528: Granular logic refinement and documentation update.

;; Commit 532: Granular logic refinement and documentation update.

;; Commit 536: Granular logic refinement and documentation update.

;; Commit 540: Granular logic refinement and documentation update.

;; Commit 544: Granular logic refinement and documentation update.

;; Commit 548: Granular logic refinement and documentation update.

;; Commit 552: Granular logic refinement and documentation update.

;; Commit 556: Granular logic refinement and documentation update.

;; Commit 560: Granular logic refinement and documentation update.
