OPNet Escrow Marketplace

Deterministic peer-to-peer service exchange protocol built on OPNet.

Status

Testnet deployed and fully functional.

Overview

OPNet Escrow Marketplace is a trust-minimized escrow protocol designed for direct service exchange between users without intermediaries.

The contract implements a deterministic state machine that enforces secure fund locking, controlled state transitions, and automated resolution via timeout logic.

This project demonstrates a programmable escrow primitive built natively on OPNet.

Core Features

OP20 token implementation

Deterministic escrow state machine

Escrow lifecycle:

Created

Accepted

Funded

Completed

Disputed

Locked balance accounting

Supply cap enforcement

Reentrancy protection

Timeout-based cancellation

Controlled faucet logic (testnet only)

Escrow invariant enforcement

Escrow State Machine

CREATED → ACCEPTED → FUNDED → COMPLETED
↘
DISPUTED

All transitions are strictly validated.

Invalid transitions revert execution.

Security Model

The protocol enforces multiple safety guarantees:

Reentrancy Guard

All state mutations are protected against reentrancy.

Supply Cap

Token minting is strictly capped by maximum supply.

Escrow Invariant

The contract enforces:

contractBalance ≥ totalLocked

This ensures all locked escrow funds remain fully backed.

Timeout Protection

Escrows include timeout logic to prevent indefinite capital lock.

Architecture

The protocol consists of:

Settlement Layer (OP20 token)

Escrow Engine (state machine logic)

Locked Balance Accounting System

Invariant Enforcement Mechanism

The system is designed to be minimal, deterministic, and composable.

Future Improvements

Governance-based token issuance

Arbitration layer for dispute resolution

Frontend interface

Mainnet-ready economic model

Protocol-level fee mechanism

Repository Structure

contracts/
└── EscrowMarketplace.ts

License

MIT License
