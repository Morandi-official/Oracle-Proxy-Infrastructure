# Phase 1 Production Control State Machine

Status: engineering design checkpoint

## Objective

Move from the current safety-only control boundary toward a production-shaped VPN control path without enabling unsafe network mutation.

The current service intentionally rejects tunnel operations because WFP fail-closed verification is not yet present. This document defines the transition requirements.

## State model

```
OFFLINE
  |
  | authenticated connect request
  v
PREPARING_POLICY
  |
  | WFP verifier confirms owned fail-closed policy
  v
POLICY_ARMED
  |
  | tunnel engine start succeeds
  v
CONNECTED
  |
  | disconnect request / failure
  v
DISCONNECTING
  |
  | owned resources removed and network restored
  v
OFFLINE
```

## Required invariants

- GUI never owns privileged network operations.
- Service accepts only authenticated fixed profiles.
- Tunnel start is impossible unless policy readiness is verified by the SYSTEM-owned verifier.
- Disconnect must remove only resources owned by this product.
- Crash recovery must leave the machine recoverable.

## Implementation sequence

1. Introduce explicit internal state transitions.
2. Add a SYSTEM-owned policy verifier interface.
3. Connect verifier result to tunnel start authorization.
4. Add rollback transaction handling.
5. Add evidence tests before enabling production builds.

## Current limitation

This file does not enable production networking. It records the implementation boundary required before that step.
