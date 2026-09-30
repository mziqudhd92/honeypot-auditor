# MongoDB probe

TCP/27017. Fingerprints `hello` with frozen `connectionId: 1`, synthetic OP_MSG
replies, `responseTo` mismatches, identical hellos across reconnects, and
unauthorized `ping` after hello.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | `ping` unauthorized after `hello` · identical hello across reconnects |
| **static_signature** | `hello` connectionId frozen at 1 · OP_MSG synthetic reply · responseTo mismatch |

## Indicators

| ID | Trigger |
|----|---------|
| `mongodb.signature` | Frozen connectionId / stock hello shape |
| `mongodb.op_msg` | Synthetic OP_MSG facade |
| `mongodb.response_to` | Wire `responseTo` ≠ client `requestId` |
| `mongodb.persist` | `ping` unauthorized after successful hello |
| `mongodb.hello_clone` | Bitwise-identical hello across reconnects |

## Non-destructive policy

`hello` / `ping` only. Never reads collections or writes documents.

## Ports

| Port | Mode |
|------|------|
| 27017 | Production / lab MongoDB |
