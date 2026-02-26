// ============================================================
//  ServiceMarketplace.ts
//  OPNet P2P Service Marketplace — v5.1 (Production)
//
//  UPGRADES vs v5:
//   [U5.1-1] FAUCET — permissionless, cooldown-gated token issuance.
//            claimFaucet() mints FAUCET_AMOUNT to Blockchain.sender
//            if and only if:
//              (a) sender is non-zero
//              (b) cooldown of FAUCET_COOLDOWN blocks has elapsed
//                  since the sender's last successful claim
//              (c) totalSupply + FAUCET_AMOUNT <= TOKEN_MAX_SUPPLY
//            No owner, no admin, no privileged mint.  Max supply cap
//            is structurally enforced.  Reentrancy guard applied.
//   [U5.1-2] PTR_LAST_CLAIM — per-address storage pointer recording
//            the block number of each address's last faucet claim.
//
//  PRESERVED FROM v5:
//   [U5-1] ACCEPT_TIMEOUT_BLOCKS + PTR_ACCEPTED_AT
//   [U5-2] sweepExcess()
//   [U5-3] In-frame reentrancy guard (_locked bool, _lock/_unlock)
//   [U5-4] Explicit zero-address validation on all actor addresses
//   [V4-U1] _requireOrderExists()
//   [V4-U2] STATE_ACCEPTED — buyer registration is state-based
//   [V4-U3] PTR_TOTAL_LOCKED — global escrow accounting register
//   [V4-U4] _transition(orderId, from, to) — formal state machine guard
//   [V3]    callMethod() dispatch; Blockchain.sender; blockNumber.toU64()
//           Blockchain.getStorageAt/setStorageAt; native balanceOfMap escrow
//           SafeMath; Checks-Effects-Interactions; no owner/admin/Solidity
//
//  COMPLETE STATE MACHINE:
//
//   createOrder       acceptOrder      fundOrder    confirmCompletion
//   ──────────► CREATED ──────► ACCEPTED ──────► FUNDED ──────────► COMPLETED
//                  │                │                 │               (terminal)
//          cancel  │  deadline      │  timeout        │  openDispute
//          (seller │  expired       │  expired        │  (buyer/seller)
//          or any) │                │                 ▼
//                  ▼                ▼              DISPUTED
//              CANCELLED        CANCELLED            │
//              (terminal)       (terminal)    cancel │ (buyer only,
//                                             after  │  deadline +
//                                             timeout)│ DISPUTE_TIMEOUT)
//                                                     ▼
//                                                 CANCELLED
//                                                 (terminal)
//
//  STORAGE LAYOUT:
//   PTR 0x0001 → global order counter         subPtr = u256.Zero
//   PTR 0x0010 → seller Address per orderId
//   PTR 0x0020 → buyer  Address per orderId
//   PTR 0x0030 → price  u256   per orderId
//   PTR 0x0040 → locked u256   per orderId
//   PTR 0x0050 → state  u8     per orderId   lo byte of u256
//   PTR 0x0060 → deadline u64  per orderId   lo64 of u256
//   PTR 0x0070 → totalLocked u256            subPtr = u256.Zero
//   PTR 0x0080 → acceptedAt u64 per orderId  lo64 of u256  [U5-1]
//   PTR 0x0090 → lastClaimBlock u64 per addr lo64 of u256  [U5.1-1]
// ============================================================

import {
    Address,
    Blockchain,
    BytesWriter,
    Calldata,
    DeployableOP_20,
    encodeSelector,
    NetEvent,
    OP20InitParameters,
    Revert,
    Selector,
    SafeMath,
} from '@btc-vision/btc-runtime/runtime';

import { u256 } from 'as-bignum/assembly';

// ─────────────────────────────────────────────────────────────
//  STORAGE POINTER NAMESPACES  (u16)
//
//  OPNet storage key = hash(pointer: u16, subPointer: u256).
//  Per-order fields:  subPointer = u256.fromU64(orderId)
//  Per-address:       subPointer = address.toU256()
//  Global singletons: subPointer = u256.Zero
// ─────────────────────────────────────────────────────────────
const PTR_ORDER_COUNT:  u16 = 0x0001;
const PTR_SELLER:       u16 = 0x0010;
const PTR_BUYER:        u16 = 0x0020;
const PTR_PRICE:        u16 = 0x0030;
const PTR_LOCKED:       u16 = 0x0040;
const PTR_STATE:        u16 = 0x0050;
const PTR_DEADLINE:     u16 = 0x0060;
const PTR_TOTAL_LOCKED: u16 = 0x0070;
const PTR_ACCEPTED_AT:  u16 = 0x0080; // [U5-1] block at which order was accepted
const PTR_LAST_CLAIM:   u16 = 0x0090; // [U5.1-1] last faucet claim block per address

// ─────────────────────────────────────────────────────────────
//  ORDER STATE CONSTANTS  (u8, stored in low byte of u256)
//
//  STATE_NONE = 0 is the default value of uninitialised storage.
//  _requireOrderExists() ensures no valid call acts on STATE_NONE.
// ─────────────────────────────────────────────────────────────
const STATE_NONE:      u8 = 0; // uninitialised sentinel
const STATE_CREATED:   u8 = 1; // seller listed, no buyer
const STATE_ACCEPTED:  u8 = 2; // buyer claimed, not yet funded
const STATE_FUNDED:    u8 = 3; // funds locked in escrow
const STATE_COMPLETED: u8 = 4; // delivery confirmed (terminal)
const STATE_CANCELLED: u8 = 5; // cancelled — funds returned (terminal)
const STATE_DISPUTED:  u8 = 6; // dispute raised — funds frozen

// ─────────────────────────────────────────────────────────────
//  PROTOCOL CONSTANTS
// ─────────────────────────────────────────────────────────────

// Minimum listing deadline (~1 hour at 10 min/block).
const MIN_DEADLINE_BLOCKS: u64 = 6;

// [U5-1] Window after acceptOrder within which buyer MUST fund.
// ~50 days at 10 min/block.  After this, anyone may cancel.
const ACCEPT_TIMEOUT_BLOCKS: u64 = 7200;

// After dispute, buyer may force-cancel once
// (deadline + DISPUTE_TIMEOUT_BLOCKS) elapses (~1 day).
const DISPUTE_TIMEOUT_BLOCKS: u64 = 144;

// ─────────────────────────────────────────────────────────────
//  [U5.1-1] FAUCET CONSTANTS
//
//  FAUCET_AMOUNT   — tokens minted per successful claim.
//                    100 mESC (8 decimals) = 10_000_000_000 base units.
//  FAUCET_COOLDOWN — minimum blocks between two claims by the same
//                    address.  ~1 day at 10 min/block = 144 blocks.
//
//  Neither constant grants any privilege.  Anyone may call
//  claimFaucet() on any block as long as their per-address
//  cooldown has elapsed and the global max supply is not breached.
// ─────────────────────────────────────────────────────────────
const FAUCET_AMOUNT:   u256 = u256.fromU64(10_000_000_000); // 100 mESC
const FAUCET_COOLDOWN: u64  = 144;                          // ~1 day

// ─────────────────────────────────────────────────────────────
//  BYTE-LENGTH CONSTANTS
// ─────────────────────────────────────────────────────────────
const SZ_U64:     i32 = 8;
const SZ_U256:    i32 = 32;
const SZ_ADDRESS: i32 = 20;
const SZ_U8:      i32 = 1;
const SZ_BOOL:    i32 = 1;

// ─────────────────────────────────────────────────────────────
//  ESCROW TOKEN METADATA
//
//  This contract IS an OP-20 token whose internal balanceOfMap
//  serves as the escrow vault (native OPNet balance model).
//  Max supply = 21,000,000 BTC × 10^8 satoshis.
// ─────────────────────────────────────────────────────────────
const TOKEN_NAME:       string = 'Marketplace Escrow';
const TOKEN_SYMBOL:     string = 'mESC';
const TOKEN_DECIMALS:   u8     = 8;
const TOKEN_MAX_SUPPLY: string = '2100000000000000';

// ─────────────────────────────────────────────────────────────
//  EVENTS
// ─────────────────────────────────────────────────────────────

@final
class OrderCreatedEvent extends NetEvent {
    constructor(orderId: u64, seller: Address, price: u256, deadline: u64) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS + SZ_U256 + SZ_U64);
        w.writeU64(orderId);
        w.writeAddress(seller);
        w.writeU256(price);
        w.writeU64(deadline);
        super('OrderCreated', w);
    }
}

@final
class OrderAcceptedEvent extends NetEvent {
    constructor(orderId: u64, buyer: Address, acceptedAt: u64) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS + SZ_U64);
        w.writeU64(orderId);
        w.writeAddress(buyer);
        w.writeU64(acceptedAt);
        super('OrderAccepted', w);
    }
}

@final
class OrderFundedEvent extends NetEvent {
    constructor(orderId: u64, buyer: Address, amount: u256) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS + SZ_U256);
        w.writeU64(orderId);
        w.writeAddress(buyer);
        w.writeU256(amount);
        super('OrderFunded', w);
    }
}

@final
class OrderCompletedEvent extends NetEvent {
    constructor(orderId: u64, seller: Address, amount: u256) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS + SZ_U256);
        w.writeU64(orderId);
        w.writeAddress(seller);
        w.writeU256(amount);
        super('OrderCompleted', w);
    }
}

@final
class OrderCancelledEvent extends NetEvent {
    constructor(orderId: u64, refundTo: Address, amount: u256) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS + SZ_U256);
        w.writeU64(orderId);
        w.writeAddress(refundTo);
        w.writeU256(amount);
        super('OrderCancelled', w);
    }
}

@final
class OrderDisputedEvent extends NetEvent {
    constructor(orderId: u64, raisedBy: Address) {
        const w = new BytesWriter(SZ_U64 + SZ_ADDRESS);
        w.writeU64(orderId);
        w.writeAddress(raisedBy);
        super('OrderDisputed', w);
    }
}

@final
class ExcessSweptEvent extends NetEvent {
    constructor(recipient: Address, amount: u256) {
        const w = new BytesWriter(SZ_ADDRESS + SZ_U256);
        w.writeAddress(recipient);
        w.writeU256(amount);
        super('ExcessSwept', w);
    }
}

// [U5.1-1] Emitted on every successful faucet claim.
@final
class FaucetClaimedEvent extends NetEvent {
    constructor(recipient: Address, amount: u256, claimedAt: u64) {
        const w = new BytesWriter(SZ_ADDRESS + SZ_U256 + SZ_U64);
        w.writeAddress(recipient);
        w.writeU256(amount);
        w.writeU64(claimedAt);
        super('FaucetClaimed', w);
    }
}

// ─────────────────────────────────────────────────────────────
//  MAIN CONTRACT
// ─────────────────────────────────────────────────────────────

@final
export class ServiceMarketplace extends DeployableOP_20 {

    // ─────────────────────────────────────────────────────────
    //  [U5-3] IN-FRAME REENTRANCY GUARD
    //
    //  `_locked` is a boolean field in WASM linear memory (NOT
    //  in persistent storage).  It exists only for the duration
    //  of a single call frame and resets automatically between
    //  transactions.
    //
    //  OPNet's current WASM execution model does not have EVM-
    //  style fallback reentrancy, but cross-contract calls that
    //  call back into this contract are theoretically possible in
    //  future runtime versions.  Wrapping all mutating entry
    //  points is correct defensive production practice.
    //
    //  Pattern:
    //    _requireNotLocked()  → revert if already inside a call
    //    _lock()              → set _locked = true
    //    _unlock()            → set _locked = false
    //    every mutating entry point calls _requireNotLocked() then
    //    _lock() at the top, and _unlock() before returning.
    // ─────────────────────────────────────────────────────────
    private _locked: bool = false;

    // ── Lifecycle ─────────────────────────────────────────────

    public constructor() {
        super();
        // Constructor runs on every interaction.
        // One-time initialisation goes in onDeployment().
    }

    /**
     * Runs exactly once at deployment.
     * Initialises the OP-20 token shell and both global counters.
     */
    public override onDeployment(_calldata: Calldata): void {
        const maxSupply = u256.fromString(TOKEN_MAX_SUPPLY);
        this.instantiate(new OP20InitParameters(
            maxSupply,
            TOKEN_DECIMALS,
            TOKEN_NAME,
            TOKEN_SYMBOL,
        ));

        Blockchain.setStorageAt(PTR_ORDER_COUNT,  u256.Zero, u256.Zero);
        Blockchain.setStorageAt(PTR_TOTAL_LOCKED, u256.Zero, u256.Zero);
    }

    // ─────────────────────────────────────────────────────────
    //  DISPATCH — callMethod()
    //
    //  The OPNet WASM host invokes callMethod() for every external
    //  call.  Overriding execute() or any other name would produce
    //  unreachable dead code — all marketplace selectors would
    //  silently fall through to the OP-20 base and revert.
    //
    //  Unknown selectors delegate to super.callMethod() so all
    //  OP-20 built-ins (transfer, approve, balanceOf …) remain live.
    // ─────────────────────────────────────────────────────────
    public override callMethod(method: Selector, calldata: Calldata): BytesWriter {
        switch (method) {

            case encodeSelector('createOrder(uint256,uint64)'):
                return this._createOrder(calldata);

            case encodeSelector('acceptOrder(uint64)'):
                return this._acceptOrder(calldata);

            case encodeSelector('fundOrder(uint64)'):
                return this._fundOrder(calldata);

            case encodeSelector('confirmCompletion(uint64)'):
                return this._confirmCompletion(calldata);

            case encodeSelector('cancelOrder(uint64)'):
                return this._cancelOrder(calldata);

            case encodeSelector('openDispute(uint64)'):
                return this._openDispute(calldata);

            case encodeSelector('sweepExcess()'):
                return this._sweepExcess();

            // [U5.1-1] Permissionless faucet claim.
            case encodeSelector('claimFaucet()'):
                return this._claimFaucet();

            case encodeSelector('getOrder(uint64)'):
                return this._getOrder(calldata);

            case encodeSelector('getEscrowStats()'):
                return this._getEscrowStats();

            default:
                return super.callMethod(method, calldata);
        }
    }

    // ─────────────────────────────────────────────────────────
    //  [U5-3] REENTRANCY GUARD INTERNALS
    // ─────────────────────────────────────────────────────────

    @inline
    private _requireNotLocked(): void {
        if (this._locked) {
            throw new Revert('ServiceMarketplace: reentrant call detected');
        }
    }

    @inline
    private _lock(): void {
        this._locked = true;
    }

    @inline
    private _unlock(): void {
        this._locked = false;
    }

    // ─────────────────────────────────────────────────────────
    //  STORAGE ACCESSORS
    //
    //  All reads/writes via:
    //    Blockchain.getStorageAt(pointer: u16, subPointer: u256, default: u256): u256
    //    Blockchain.setStorageAt(pointer: u16, subPointer: u256, value: u256): void
    //
    //  Per-order:   subPointer = u256.fromU64(orderId)
    //  Per-address: subPointer = address.toU256()
    //  Global:      subPointer = u256.Zero
    //
    //  Type packing:
    //    u8      → lo byte   : .lo1 & 0xFF
    //    u64     → lo 64 bits: .lo1
    //    Address → addr.toU256() / Address.fromU256()
    //    u256    → direct
    // ─────────────────────────────────────────────────────────

    @inline
    private _sub(orderId: u64): u256 {
        return u256.fromU64(orderId);
    }

    // ── State ─────────────────────────────────────────────────

    private _readState(orderId: u64): u8 {
        return <u8>(
            Blockchain.getStorageAt(PTR_STATE, this._sub(orderId), u256.Zero).lo1 & 0xFF
        );
    }

    private _writeState(orderId: u64, state: u8): void {
        Blockchain.setStorageAt(PTR_STATE, this._sub(orderId), u256.fromU32(<u32>state));
    }

    // ── Deadline ──────────────────────────────────────────────

    private _readDeadline(orderId: u64): u64 {
        return Blockchain.getStorageAt(PTR_DEADLINE, this._sub(orderId), u256.Zero).lo1;
    }

    private _writeDeadline(orderId: u64, deadline: u64): void {
        Blockchain.setStorageAt(PTR_DEADLINE, this._sub(orderId), u256.fromU64(deadline));
    }

    // ── [U5-1] Accepted-at block ──────────────────────────────

    private _readAcceptedAt(orderId: u64): u64 {
        return Blockchain.getStorageAt(PTR_ACCEPTED_AT, this._sub(orderId), u256.Zero).lo1;
    }

    private _writeAcceptedAt(orderId: u64, blockNum: u64): void {
        Blockchain.setStorageAt(PTR_ACCEPTED_AT, this._sub(orderId), u256.fromU64(blockNum));
    }

    // ── Price / Locked ────────────────────────────────────────

    private _readPrice(orderId: u64): u256 {
        return Blockchain.getStorageAt(PTR_PRICE, this._sub(orderId), u256.Zero);
    }

    private _writePrice(orderId: u64, price: u256): void {
        Blockchain.setStorageAt(PTR_PRICE, this._sub(orderId), price);
    }

    private _readLocked(orderId: u64): u256 {
        return Blockchain.getStorageAt(PTR_LOCKED, this._sub(orderId), u256.Zero);
    }

    private _writeLocked(orderId: u64, amount: u256): void {
        Blockchain.setStorageAt(PTR_LOCKED, this._sub(orderId), amount);
    }

    // ── Addresses ─────────────────────────────────────────────

    private _readSeller(orderId: u64): Address {
        return Address.fromU256(
            Blockchain.getStorageAt(PTR_SELLER, this._sub(orderId), u256.Zero)
        );
    }

    private _writeSeller(orderId: u64, addr: Address): void {
        Blockchain.setStorageAt(PTR_SELLER, this._sub(orderId), addr.toU256());
    }

    private _readBuyer(orderId: u64): Address {
        return Address.fromU256(
            Blockchain.getStorageAt(PTR_BUYER, this._sub(orderId), u256.Zero)
        );
    }

    private _writeBuyer(orderId: u64, addr: Address): void {
        Blockchain.setStorageAt(PTR_BUYER, this._sub(orderId), addr.toU256());
    }

    // ── Global counters ───────────────────────────────────────

    private _readOrderCount(): u64 {
        return Blockchain.getStorageAt(PTR_ORDER_COUNT, u256.Zero, u256.Zero).lo1;
    }

    private _nextOrderId(): u64 {
        const current: u64 = this._readOrderCount();
        if (current === u64.MAX_VALUE) {
            throw new Revert('ServiceMarketplace: order ID overflow');
        }
        const next: u64 = current + 1;
        Blockchain.setStorageAt(PTR_ORDER_COUNT, u256.Zero, u256.fromU64(next));
        return next;
    }

    private _readTotalLocked(): u256 {
        return Blockchain.getStorageAt(PTR_TOTAL_LOCKED, u256.Zero, u256.Zero);
    }

    private _writeTotalLocked(value: u256): void {
        Blockchain.setStorageAt(PTR_TOTAL_LOCKED, u256.Zero, value);
    }

    // ── [U5.1-1] Faucet last-claim block per address ──────────

    /**
     * Returns the block number of the given address's last successful
     * faucet claim.  Returns 0 for addresses that have never claimed.
     * subPointer = addr.toU256() scopes the slot uniquely per address.
     */
    private _readLastClaimBlock(addr: Address): u64 {
        return Blockchain.getStorageAt(PTR_LAST_CLAIM, addr.toU256(), u256.Zero).lo1;
    }

    private _writeLastClaimBlock(addr: Address, blockNum: u64): void {
        Blockchain.setStorageAt(PTR_LAST_CLAIM, addr.toU256(), u256.fromU64(blockNum));
    }

    // ─────────────────────────────────────────────────────────
    //  VALIDATION HELPERS
    // ─────────────────────────────────────────────────────────

    /**
     * [V4-U1] Explicit order existence guard.
     * Called at the top of every mutating and view entry point.
     * Does NOT rely on STATE_NONE as a proxy for "not found."
     */
    private _requireOrderExists(orderId: u64): void {
        if (orderId === 0) {
            throw new Revert('ServiceMarketplace: orderId 0 is invalid');
        }
        if (orderId > this._readOrderCount()) {
            throw new Revert('ServiceMarketplace: order does not exist');
        }
    }

    /**
     * [V4-U4] Formal state transition guard.
     * The sole path for all state mutations in entry functions.
     * Asserts current state == from before writing to.
     */
    private _transition(orderId: u64, from: u8, to: u8): void {
        const current = this._readState(orderId);
        if (current !== from) {
            throw new Revert(
                'ServiceMarketplace: invalid transition — current ' +
                current.toString() +
                ', expected ' + from.toString() +
                ', target '   + to.toString()
            );
        }
        this._writeState(orderId, to);
    }

    /**
     * All authentication uses Blockchain.sender exclusively.
     * Blockchain.tx.sender does not exist in OPNet runtime.
     */
    private _requireCaller(expected: Address): void {
        if (!Blockchain.sender.equals(expected)) {
            throw new Revert('ServiceMarketplace: caller not authorised');
        }
    }

    /**
     * [U5-4] Explicit zero-address check.
     * Called on seller (createOrder), buyer (acceptOrder), and
     * all release recipients before funds are moved.
     */
    private _requireNonZeroAddress(addr: Address): void {
        if (u256.eq(addr.toU256(), u256.Zero)) {
            throw new Revert('ServiceMarketplace: zero address not allowed');
        }
    }

    /**
     * Blockchain.blockNumber returns u256.
     * Always .toU64() before u64 comparisons.
     */
    @inline
    private _currentBlock(): u64 {
        return Blockchain.blockNumber.toU64();
    }

    private _requireDeadlineNotExpired(orderId: u64): void {
        if (this._currentBlock() > this._readDeadline(orderId)) {
            throw new Revert('ServiceMarketplace: deadline expired');
        }
    }

    private _isDeadlineExpired(orderId: u64): bool {
        return this._currentBlock() > this._readDeadline(orderId);
    }

    @inline
    private _isZeroAddress(addr: Address): bool {
        return u256.eq(addr.toU256(), u256.Zero);
    }

    // ─────────────────────────────────────────────────────────
    //  NATIVE OP-20 BALANCE ESCROW  +  GLOBAL ACCOUNTING
    //
    //  balanceOfMap (AddressMemoryMap<u256>) is inherited from
    //  DeployableOP_20 and IS the OP-20 token ledger.
    //  Escrow = in-frame mutations of this map.
    //
    //  [V4-U3] Every lock/release also updates PTR_TOTAL_LOCKED.
    //
    //  Strengthened invariant (enforced in _escrowRelease):
    //    contractBalance >= totalLocked
    //
    //  This invariant fires if any path drains contractBalance
    //  without a matching totalLocked decrement — e.g., a direct
    //  OP-20 transfer() call targeting the contract address.
    // ─────────────────────────────────────────────────────────

    /**
     * Lock `amount` from payer into contract escrow.
     *
     *   payer.balanceOfMap    -= amount
     *   contract.balanceOfMap += amount
     *   totalLocked           += amount
     *
     * Reverts if payer balance < amount.
     */
    private _escrowLock(payer: Address, amount: u256): void {
        const payerBal: u256    = this.balanceOfMap.get(payer);
        const contractAddr       = Blockchain.contractAddress;
        const contractBal: u256 = this.balanceOfMap.get(contractAddr);

        if (u256.lt(payerBal, amount)) {
            throw new Revert('ServiceMarketplace: insufficient OP-20 balance to fund escrow');
        }

        const newPayer:    u256 = SafeMath.sub(payerBal,             amount);
        const newContract: u256 = SafeMath.add(contractBal,          amount);
        const newTotal:    u256 = SafeMath.add(this._readTotalLocked(), amount);

        this.balanceOfMap.set(payer,        newPayer);
        this.balanceOfMap.set(contractAddr, newContract);
        this._writeTotalLocked(newTotal);
    }

    /**
     * Release `amount` from contract escrow to recipient.
     *
     *   contract.balanceOfMap -= amount
     *   recipient.balanceOfMap += amount
     *   totalLocked            -= amount
     *
     * [U5-4] Validates recipient is non-zero before any transfer.
     *
     * Three-layer guard:
     *   (1) contractBalance >= totalLocked   (global invariant)
     *   (2) totalLocked     >= amount        (underflow guard on register)
     *   (3) contractBalance >= amount        (direct sufficiency check)
     */
    private _escrowRelease(recipient: Address, amount: u256): void {
        if (u256.eq(amount, u256.Zero)) return;

        // [U5-4] Never release to zero address.
        this._requireNonZeroAddress(recipient);

        const contractAddr       = Blockchain.contractAddress;
        const contractBal: u256 = this.balanceOfMap.get(contractAddr);
        const totalLocked: u256 = this._readTotalLocked();

        // Guard (1): primary invariant.
        if (u256.lt(contractBal, totalLocked)) {
            throw new Revert(
                'ServiceMarketplace: CRITICAL — escrow invariant violated: ' +
                'contractBalance < totalLocked'
            );
        }
        // Guard (2): register underflow.
        if (u256.lt(totalLocked, amount)) {
            throw new Revert(
                'ServiceMarketplace: CRITICAL — release amount exceeds totalLocked'
            );
        }
        // Guard (3): direct sufficiency.
        if (u256.lt(contractBal, amount)) {
            throw new Revert(
                'ServiceMarketplace: CRITICAL — contract balance insufficient for release'
            );
        }

        const recipientBal: u256 = this.balanceOfMap.get(recipient);

        const newContract:  u256 = SafeMath.sub(contractBal,  amount);
        const newRecipient: u256 = SafeMath.add(recipientBal, amount);
        const newTotal:     u256 = SafeMath.sub(totalLocked,  amount);

        // All writes after all checks (Checks-Effects-Interactions).
        this.balanceOfMap.set(contractAddr, newContract);
        this.balanceOfMap.set(recipient,    newRecipient);
        this._writeTotalLocked(newTotal);
    }

    // ─────────────────────────────────────────────────────────
    //  ENTRY POINTS
    // ─────────────────────────────────────────────────────────

    /**
     * createOrder(price: u256, deadlineBlocks: u64) → orderId: u64
     *
     * Seller creates a new service listing.
     * `deadlineBlocks` is relative; stored as absolute block height.
     *
     * [U5-3] Reentrancy guard.
     * [U5-4] Explicit seller non-zero check.
     *
     * Requirements:
     *   • caller is non-zero
     *   • price > 0
     *   • deadlineBlocks >= MIN_DEADLINE_BLOCKS
     *
     * State after: CREATED
     * Emits:       OrderCreated
     */
    private _createOrder(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const price: u256     = calldata.readU256();
        const dBlocks: u64    = calldata.readU64();
        const seller: Address = Blockchain.sender;

        // [U5-4]
        this._requireNonZeroAddress(seller);

        if (u256.eq(price, u256.Zero)) {
            this._unlock();
            throw new Revert('ServiceMarketplace: price must be > 0');
        }
        if (dBlocks < MIN_DEADLINE_BLOCKS) {
            this._unlock();
            throw new Revert(
                'ServiceMarketplace: deadline below minimum (' +
                MIN_DEADLINE_BLOCKS.toString() + ' blocks)'
            );
        }

        const orderId: u64 = this._nextOrderId();
        const block: u64   = this._currentBlock();

        if (block > u64.MAX_VALUE - dBlocks) {
            this._unlock();
            throw new Revert('ServiceMarketplace: deadline overflows u64');
        }
        const deadlineAbs: u64 = block + dBlocks;

        // Initialise all storage fields.  _writeState is used directly
        // here because this is initialisation from scratch, not a
        // transition from a prior persisted state.
        this._writeSeller(orderId, seller);
        this._writeBuyer(orderId, Address.fromU256(u256.Zero));
        this._writePrice(orderId, price);
        this._writeLocked(orderId, u256.Zero);
        this._writeDeadline(orderId, deadlineAbs);
        this._writeAcceptedAt(orderId, 0);   // [U5-1] zero = never accepted
        this._writeState(orderId, STATE_CREATED);

        this.emitEvent(new OrderCreatedEvent(orderId, seller, price, deadlineAbs));

        this._unlock();

        const out = new BytesWriter(SZ_U64);
        out.writeU64(orderId);
        return out;
    }

    /**
     * acceptOrder(orderId: u64) → bool
     *
     * Buyer registers intent.  Transitions CREATED → ACCEPTED.
     * Records acceptedAt block for the funding timeout window.
     *
     * [U5-1] Stores acceptedAt = currentBlock.
     * [U5-3] Reentrancy guard.
     * [U5-4] Explicit buyer non-zero check.
     * [V4-U1] Order existence guard.
     * [V4-U4] _transition enforces CREATED → ACCEPTED atomically.
     *
     * Requirements:
     *   • orderId exists
     *   • state == CREATED
     *   • deadline not expired
     *   • caller ≠ seller
     *   • caller is non-zero
     *
     * State after: ACCEPTED
     * Emits:       OrderAccepted
     */
    private _acceptOrder(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const orderId: u64    = calldata.readU64();
        const buyer: Address  = Blockchain.sender;

        // [V4-U1]
        this._requireOrderExists(orderId);

        // [U5-4]
        this._requireNonZeroAddress(buyer);

        this._requireDeadlineNotExpired(orderId);

        const seller = this._readSeller(orderId);

        if (buyer.equals(seller)) {
            this._unlock();
            throw new Revert('ServiceMarketplace: seller cannot accept own order');
        }

        const block: u64 = this._currentBlock();

        // [V4-U4] CREATED → ACCEPTED.
        this._transition(orderId, STATE_CREATED, STATE_ACCEPTED);

        // Persist buyer address and acceptedAt timestamp.
        this._writeBuyer(orderId, buyer);
        this._writeAcceptedAt(orderId, block); // [U5-1]

        this.emitEvent(new OrderAcceptedEvent(orderId, buyer, block));

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * fundOrder(orderId: u64) → bool
     *
     * Buyer locks the order price into contract escrow.
     *
     * [U5-3] Reentrancy guard.
     * [V4-U1] Order existence guard.
     * [V4-U2] Requires STATE_ACCEPTED — no buyer-address inspection.
     * [V4-U3] _escrowLock increments totalLocked atomically.
     * [V4-U4] _transition enforces ACCEPTED → FUNDED.
     *
     * Balance model:
     *   buyer.balanceOfMap    -= price
     *   contract.balanceOfMap += price
     *   totalLocked           += price
     *
     * Requirements:
     *   • orderId exists
     *   • state == ACCEPTED
     *   • caller == registered buyer
     *   • deadline not expired
     *   • accept timeout not exceeded (within ACCEPT_TIMEOUT_BLOCKS)
     *   • buyer OP-20 balance >= price
     *
     * State after: FUNDED
     * Emits:       OrderFunded
     */
    private _fundOrder(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const orderId: u64 = calldata.readU64();

        // [V4-U1]
        this._requireOrderExists(orderId);

        this._requireDeadlineNotExpired(orderId);

        const buyer = this._readBuyer(orderId);

        // [U5-4]
        this._requireNonZeroAddress(buyer);
        this._requireCaller(buyer);

        // [U5-1] Buyer must fund within ACCEPT_TIMEOUT_BLOCKS.
        const acceptedAt: u64 = this._readAcceptedAt(orderId);
        const block: u64      = this._currentBlock();
        const fundDeadline: u64 = (acceptedAt > u64.MAX_VALUE - ACCEPT_TIMEOUT_BLOCKS)
            ? u64.MAX_VALUE
            : acceptedAt + ACCEPT_TIMEOUT_BLOCKS;

        if (block > fundDeadline) {
            this._unlock();
            throw new Revert('ServiceMarketplace: accept timeout expired — buyer must re-accept');
        }

        const price = this._readPrice(orderId);

        // ── CHECKS-EFFECTS-INTERACTIONS ──────────────────────
        // [V4-U4] ACCEPTED → FUNDED.
        this._transition(orderId, STATE_ACCEPTED, STATE_FUNDED);
        this._writeLocked(orderId, price);

        // [V4-U3] Lock — updates balanceOfMap AND totalLocked.
        this._escrowLock(buyer, price);

        this.emitEvent(new OrderFundedEvent(orderId, buyer, price));

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * confirmCompletion(orderId: u64) → bool
     *
     * Buyer confirms off-chain service delivery.
     * Releases escrowed funds to seller.
     *
     * [U5-3] Reentrancy guard.
     * [U5-4] Seller non-zero check before release.
     * [V4-U1] Order existence guard.
     * [V4-U3] _escrowRelease decrements totalLocked atomically.
     * [V4-U4] _transition enforces FUNDED → COMPLETED.
     *
     * Balance model:
     *   contract.balanceOfMap -= locked
     *   seller.balanceOfMap   += locked
     *   totalLocked           -= locked
     *
     * Requirements:
     *   • orderId exists
     *   • state == FUNDED
     *   • caller == buyer
     *   (Confirmation is valid even after deadline — deadline gates
     *    cancellation only, not confirmation.)
     *
     * State after: COMPLETED (terminal)
     * Emits:       OrderCompleted
     */
    private _confirmCompletion(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const orderId: u64 = calldata.readU64();

        // [V4-U1]
        this._requireOrderExists(orderId);

        const buyer  = this._readBuyer(orderId);
        const seller = this._readSeller(orderId);

        // [U5-4]
        this._requireNonZeroAddress(buyer);
        this._requireNonZeroAddress(seller);

        this._requireCaller(buyer);

        const locked = this._readLocked(orderId);
        if (u256.eq(locked, u256.Zero)) {
            this._unlock();
            throw new Revert('ServiceMarketplace: invariant error — locked is zero in FUNDED state');
        }

        // ── CHECKS-EFFECTS-INTERACTIONS ──────────────────────
        // [V4-U4] FUNDED → COMPLETED committed before release.
        this._transition(orderId, STATE_FUNDED, STATE_COMPLETED);
        this._writeLocked(orderId, u256.Zero);

        // [V4-U3]
        this._escrowRelease(seller, locked);

        this.emitEvent(new OrderCompletedEvent(orderId, seller, locked));

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * cancelOrder(orderId: u64) → bool
     *
     * Multi-path cancellation function handling four distinct states.
     * Each state has its own eligibility rules and refund routing.
     *
     * [U5-1] ACCEPTED state: cancellable after accept timeout.
     * [U5-3] Reentrancy guard.
     * [U5-4] Address non-zero checks before any escrow release.
     * [V4-U1] Order existence guard.
     * [V4-U3] _escrowRelease decrements totalLocked atomically.
     * [V4-U4] _transition enforces each from→to atomically.
     *
     * ── Cancellation rules by state ──────────────────────────
     *
     *  CREATED  → seller or any party after deadline
     *             No funds to refund; buyer slot is zero.
     *
     *  ACCEPTED → any party after accept timeout expires
     *             [U5-1] fundDeadline = acceptedAt + ACCEPT_TIMEOUT_BLOCKS
     *             No funds locked; no refund needed.
     *
     *  FUNDED   → seller at any time (refund to buyer)
     *             OR buyer after deadline (refund to buyer)
     *             Releases locked funds back to buyer.
     *
     *  DISPUTED → buyer only after deadline + DISPUTE_TIMEOUT_BLOCKS
     *             Releases locked funds back to buyer.
     *
     * Emits: OrderCancelled
     */
    private _cancelOrder(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const orderId: u64    = calldata.readU64();
        const caller: Address = Blockchain.sender;
        const block: u64      = this._currentBlock();

        // [V4-U1]
        this._requireOrderExists(orderId);

        const state: u8 = this._readState(orderId);

        if (state === STATE_CREATED) {
            // ── Created — seller or deadline ──────────────────
            const seller = this._readSeller(orderId);

            if (!caller.equals(seller) && !this._isDeadlineExpired(orderId)) {
                this._unlock();
                throw new Revert(
                    'ServiceMarketplace: only seller may cancel before deadline'
                );
            }

            // [V4-U4] CREATED → CANCELLED.
            this._transition(orderId, STATE_CREATED, STATE_CANCELLED);

            // No funds were locked; emit with zero amount.
            this.emitEvent(new OrderCancelledEvent(orderId, seller, u256.Zero));

        } else if (state === STATE_ACCEPTED) {
            // ── Accepted — any party after accept timeout ──────
            const acceptedAt: u64   = this._readAcceptedAt(orderId);
            const fundDeadline: u64 = (acceptedAt > u64.MAX_VALUE - ACCEPT_TIMEOUT_BLOCKS)
                ? u64.MAX_VALUE
                : acceptedAt + ACCEPT_TIMEOUT_BLOCKS;

            if (block <= fundDeadline) {
                this._unlock();
                throw new Revert(
                    'ServiceMarketplace: accept timeout has not elapsed yet'
                );
            }

            // [V4-U4] ACCEPTED → CANCELLED.
            this._transition(orderId, STATE_ACCEPTED, STATE_CANCELLED);

            const seller = this._readSeller(orderId);
            this.emitEvent(new OrderCancelledEvent(orderId, seller, u256.Zero));

        } else if (state === STATE_FUNDED) {
            // ── Funded — seller anytime, buyer after deadline ──
            const seller = this._readSeller(orderId);
            const buyer  = this._readBuyer(orderId);
            const locked = this._readLocked(orderId);

            if (!caller.equals(seller)) {
                if (!caller.equals(buyer) || !this._isDeadlineExpired(orderId)) {
                    this._unlock();
                    throw new Revert(
                        'ServiceMarketplace: only seller may cancel before deadline'
                    );
                }
            }

            // [U5-4]
            this._requireNonZeroAddress(buyer);

            // [V4-U4] State and locked zeroed before release.
            this._transition(orderId, STATE_FUNDED, STATE_CANCELLED);
            this._writeLocked(orderId, u256.Zero);

            // [V4-U3]
            this._escrowRelease(buyer, locked);

            this.emitEvent(new OrderCancelledEvent(orderId, buyer, locked));

        } else if (state === STATE_DISPUTED) {
            // ── Disputed — buyer force-refund after timeout ────
            const deadline       = this._readDeadline(orderId);
            const forceRefundAt: u64 = (deadline > u64.MAX_VALUE - DISPUTE_TIMEOUT_BLOCKS)
                ? u64.MAX_VALUE
                : deadline + DISPUTE_TIMEOUT_BLOCKS;

            if (block < forceRefundAt) {
                this._unlock();
                throw new Revert('ServiceMarketplace: dispute timeout has not elapsed yet');
            }

            const buyer = this._readBuyer(orderId);

            if (!caller.equals(buyer)) {
                this._unlock();
                throw new Revert('ServiceMarketplace: only buyer may force-cancel after dispute timeout');
            }

            // [U5-4]
            this._requireNonZeroAddress(buyer);

            const locked = this._readLocked(orderId);

            // [V4-U4] State and locked zeroed before release.
            this._transition(orderId, STATE_DISPUTED, STATE_CANCELLED);
            this._writeLocked(orderId, u256.Zero);

            // [V4-U3]
            this._escrowRelease(buyer, locked);

            this.emitEvent(new OrderCancelledEvent(orderId, buyer, locked));

        } else {
            this._unlock();
            throw new Revert(
                'ServiceMarketplace: order not cancellable in state ' +
                state.toString()
            );
        }

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * openDispute(orderId: u64) → bool
     *
     * Either buyer or seller may dispute a FUNDED order.
     * Funds remain locked.  State transitions to DISPUTED.
     *
     * Trust-minimised design:
     *   Funds are NOT auto-released on dispute — auto-release
     *   would allow a bad actor to manufacture a dispute and
     *   steal escrowed value.  Funds are frozen until the buyer
     *   force-cancels after DISPUTE_TIMEOUT_BLOCKS via cancelOrder.
     *
     * [U5-3] Reentrancy guard.
     * [V4-U1] Existence guard.
     * [V4-U4] _transition enforces FUNDED → DISPUTED.
     *
     * State after: DISPUTED
     * Emits:       OrderDisputed
     */
    private _openDispute(calldata: Calldata): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const orderId: u64 = calldata.readU64();

        // [V4-U1]
        this._requireOrderExists(orderId);

        const caller = Blockchain.sender;
        const seller = this._readSeller(orderId);
        const buyer  = this._readBuyer(orderId);

        if (!caller.equals(buyer) && !caller.equals(seller)) {
            this._unlock();
            throw new Revert('ServiceMarketplace: only buyer or seller may open a dispute');
        }

        // [V4-U4]
        this._transition(orderId, STATE_FUNDED, STATE_DISPUTED);

        this.emitEvent(new OrderDisputedEvent(orderId, caller));

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * sweepExcess() → bool   [U5-2]
     *
     * Transfers any contract OP-20 balance above totalLocked to
     * the caller (Blockchain.sender).
     *
     * This handles excess that can accumulate from:
     *   • Direct token transfers to the contract address.
     *   • Future protocol fee additions.
     *
     * Design properties:
     *   • No owner restriction — consistent with the no-admin design.
     *     Any caller receives the excess; first caller wins.
     *   • Cannot touch locked funds — excess is computed as
     *     (contractBalance - totalLocked) so locked funds are
     *     structurally unreachable.
     *   • No-op when excess == 0.
     *   • [U5-3] Reentrancy guard.
     *
     * Emits: ExcessSwept (only if excess > 0)
     */
    private _sweepExcess(): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const recipient      = Blockchain.sender;
        const contractAddr   = Blockchain.contractAddress;
        const contractBal    = this.balanceOfMap.get(contractAddr);
        const totalLocked    = this._readTotalLocked();

        // [U5-4]
        this._requireNonZeroAddress(recipient);

        if (u256.gt(contractBal, totalLocked)) {
            const excess: u256 = SafeMath.sub(contractBal, totalLocked);

            const recipientBal  = this.balanceOfMap.get(recipient);
            const newContract   = SafeMath.sub(contractBal, excess);
            const newRecipient  = SafeMath.add(recipientBal, excess);

            // Note: sweepExcess does NOT affect totalLocked because
            // excess by definition is contractBalance - totalLocked,
            // i.e. the portion of contractBalance NOT accounted for
            // by any locked order.  Decrementing totalLocked here
            // would corrupt the accounting for all active orders.
            this.balanceOfMap.set(contractAddr, newContract);
            this.balanceOfMap.set(recipient,    newRecipient);

            this.emitEvent(new ExcessSweptEvent(recipient, excess));
        }

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    /**
     * claimFaucet() → bool   [U5.1-1]
     *
     * Permissionless token faucet.  Mints FAUCET_AMOUNT to
     * Blockchain.sender subject to three guards enforced in order:
     *
     *  (1) Sender must be non-zero.
     *      Zero-address mints are structurally meaningless and
     *      would silently burn supply against the cap.
     *
     *  (2) Cooldown: block.number - lastClaimBlock >= FAUCET_COOLDOWN
     *      Prevents a single address from draining supply in rapid
     *      succession.  First-ever claim always passes (lastClaim = 0).
     *      Overflow-safe: block can never be less than lastClaim in
     *      a valid chain, but we use saturating subtraction style via
     *      explicit comparison to be defensive.
     *
     *  (3) Supply cap: totalSupply + FAUCET_AMOUNT <= TOKEN_MAX_SUPPLY
     *      Uses SafeMath.add() to detect overflow and compares against
     *      the u256 parsed from TOKEN_MAX_SUPPLY.  Guarantees the
     *      max supply is structurally unreachable.
     *
     * On success:
     *   • sender.balanceOfMap  += FAUCET_AMOUNT   (via this.mint)
     *   • totalSupply          += FAUCET_AMOUNT   (tracked by OP-20 base)
     *   • lastClaimBlock[sender] = currentBlock
     *
     * No owner check.  No admin.  No privileged mint.
     * Escrow accounting (totalLocked) is not touched — faucet tokens
     * go directly to the sender's wallet balance, not into escrow.
     *
     * [U5-3] Reentrancy guard.
     * [U5-4] Non-zero sender check.
     *
     * Emits: FaucetClaimed
     */
    private _claimFaucet(): BytesWriter {
        // [U5-3]
        this._requireNotLocked();
        this._lock();

        const sender: Address = Blockchain.sender;
        const block: u64      = this._currentBlock();

        // Guard (1): [U5-4] sender must be non-zero.
        this._requireNonZeroAddress(sender);

        // Guard (2): cooldown per address.
        const lastClaim: u64 = this._readLastClaimBlock(sender);
        if (lastClaim !== 0) {
            // Safe: block is always >= lastClaim in a valid chain;
            // any node manipulation would cause the block comparison
            // to fail the cooldown check — not underflow into wrong state.
            if (block < lastClaim || block - lastClaim < FAUCET_COOLDOWN) {
                this._unlock();
                throw new Revert(
                    'ServiceMarketplace: faucet cooldown has not elapsed yet'
                );
            }
        }

        // Guard (3): max supply cap.
        const maxSupply: u256    = u256.fromString(TOKEN_MAX_SUPPLY);
        const currentSupply: u256 = this.totalSupply;
        const newSupply: u256     = SafeMath.add(currentSupply, FAUCET_AMOUNT);

        if (u256.gt(newSupply, maxSupply)) {
            this._unlock();
            throw new Revert(
                'ServiceMarketplace: faucet would exceed max supply'
            );
        }

        // ── CHECKS-EFFECTS-INTERACTIONS ──────────────────────
        // Update cooldown clock before mint to prevent any
        // hypothetical reentrancy re-entry claiming twice.
        this._writeLastClaimBlock(sender, block);

        // Mint FAUCET_AMOUNT directly to sender.
        // this.mint() updates both balanceOfMap[sender] and totalSupply
        // atomically inside the OP-20 base implementation.
        // totalLocked is NOT modified — faucet tokens are not escrowed.
        this.mint(sender, FAUCET_AMOUNT);

        this.emitEvent(new FaucetClaimedEvent(sender, FAUCET_AMOUNT, block));

        this._unlock();

        const out = new BytesWriter(SZ_BOOL);
        out.writeBoolean(true);
        return out;
    }

    // ─────────────────────────────────────────────────────────
    //  VIEW METHODS
    // ─────────────────────────────────────────────────────────

    /**
     * getOrder(orderId: u64) → 129-byte encoded order
     *
     * Pure view — no state mutation.
     * [V4-U1] Existence guard.
     *
     * Return layout (129 bytes):
     *   u64  orderId      ( 8)
     *   addr seller       (20)
     *   addr buyer        (20)
     *   u256 price        (32)
     *   u256 locked       (32)
     *   u8   state        ( 1)
     *   u64  deadline     ( 8)
     *   u64  acceptedAt   ( 8)   [U5-1]
     */
    private _getOrder(calldata: Calldata): BytesWriter {
        const orderId: u64 = calldata.readU64();

        // [V4-U1]
        this._requireOrderExists(orderId);

        const out = new BytesWriter(
            SZ_U64  + SZ_ADDRESS + SZ_ADDRESS +
            SZ_U256 + SZ_U256   +
            SZ_U8   + SZ_U64    + SZ_U64
        );

        out.writeU64(orderId);
        out.writeAddress(this._readSeller(orderId));
        out.writeAddress(this._readBuyer(orderId));
        out.writeU256(this._readPrice(orderId));
        out.writeU256(this._readLocked(orderId));
        out.writeU8(this._readState(orderId));
        out.writeU64(this._readDeadline(orderId));
        out.writeU64(this._readAcceptedAt(orderId));  // [U5-1]

        return out;
    }

    /**
     * getEscrowStats() → 72-byte encoded stats
     *
     * Exposes the invariant variables for off-chain monitoring.
     * A healthy contract always satisfies contractBalance >= totalLocked.
     * Any divergence should trigger an immediate off-chain alert.
     *
     * Return layout (72 bytes):
     *   u256 contractBalance (32)
     *   u256 totalLocked     (32)
     *   u64  orderCount      ( 8)
     */
    private _getEscrowStats(): BytesWriter {
        const contractBal = this.balanceOfMap.get(Blockchain.contractAddress);
        const totalLocked = this._readTotalLocked();
        const orderCount  = this._readOrderCount();

        const out = new BytesWriter(SZ_U256 + SZ_U256 + SZ_U64);
        out.writeU256(contractBal);
        out.writeU256(totalLocked);
        out.writeU64(orderCount);
        return out;
    }
}
