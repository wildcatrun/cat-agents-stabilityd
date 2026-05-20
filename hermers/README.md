# Hermers Stability Adapter Contract

This directory records the Hermers-side contract for `cat-agents-stability`.

The first implementation target is a probe/adapter package, not a migration of workflow ownership into Hermers.

## Probe

`hermers_stability_probe.py` is a read-only Hermers-side probe.

```bash
python3 hermers/hermers_stability_probe.py
python3 hermers/hermers_stability_probe.py --profiles catnose,catbody
```

It checks profile gateway service state, gateway process visibility, ACP worker observations, recent workflow runtime runs, and an IM ownership placeholder. It does not start services, kill workers, change Telegram consumers, mutate workflow state, or disable OpenClaw route-shell records.

## Required Probe Outputs

Each Hermers-side probe should return structured JSON:

```json
{
  "checkedAt": "2026-05-20T00:00:00Z",
  "profile": "cateyes",
  "agentId": "cat_eyes",
  "ready": true,
  "liveness": "ok",
  "readiness": "ok",
  "acp": {
    "available": true,
    "lastTurnStatus": "acked",
    "lastFailureType": ""
  },
  "im": {
    "telegramConsumer": "hermers",
    "duplicateConsumerDetected": false,
    "lastInboundAt": "",
    "lastOutboundReceiptAt": ""
  },
  "findings": []
}
```

## Invariants

- Hermers may own direct IM ingress for migrated agents only after explicit migration.
- OpenClaw dormant legacy identities must not receive dispatches or Telegram updates.
- All inbound and outbound messages must still map to the shared message_flow contract.
- Stability findings should be consumed by cat-brain `main` and by local Codex MCP.
