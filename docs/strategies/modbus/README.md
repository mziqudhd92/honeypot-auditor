# Modbus TCP probe

TCP/**502** (lab **1502**) — MODBUS Application Protocol specification V1.1b3
over TCP (MBAP). Targets ICS/OT deception (Conpot, Gridpot-class decoys).
Strategies are spec-behavioral — no vendor or PLC signatures.

## Strategies

| Strategy | Axis |
|----------|------|
| **state_nonpersist** | MBAP transaction ID not echoed across two requests |
| **static_signature** | MBAP framing · broadcast answered · undefined function served · illegal quantity served |

## Indicators

| ID | Trigger |
|----|---------|
| `modbus.trnid_echo` | No response echoed its transaction ID (spec: the response carries the request's) — canned responder |
| `modbus.framing` | Protocol ID ≠ 0, MBAP length ≠ delivered bytes, or truncated frame |
| `modbus.broadcast_reply` | A broadcast (unit ID 255) request drew a response — the spec requires silence |
| `modbus.illegal_function` | Unassigned function code 0x4f answered with data instead of exception 01 (ILLEGAL FUNCTION) |
| `modbus.quantity_check` | Read Coils with quantity 2001 (> spec max 2000) answered with data instead of exception 03 (ILLEGAL DATA VALUE) |

Real PLCs and gateways echo the transaction ID, validate function codes and
quantities, and never answer broadcasts. Gateways reach silent serial slaves
via exception 0x0B — any exception counts as conformant for the
function/quantity tells, so honest gateways stay clean.

## Non-destructive policy

Read-only requests only (Read Coils) plus one unassigned function code.
Never writes coils/registers/files, never touches file transfer functions.

## Ports

| Port | Mode |
|------|------|
| 502 | Production Modbus TCP |
| 1502 | Lab |
