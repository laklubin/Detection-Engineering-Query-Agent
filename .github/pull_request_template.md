## Summary

<!-- What changes and why. -->

## Detection engineering impact

- [ ] Field mappings added or changed (documented in `docs/FIELD-MAPPINGS.md`)
- [ ] Adapter output changed (tests updated)
- [ ] New telemetry family or log source added to the allowlist

## Security checklist

- [ ] No secret, token, key or customer data is added to the repository
- [ ] Guardrail and sanitisation behaviour is unchanged, or tests cover the change
- [ ] No new way for model output to reach executable context
- [ ] Generated output remains read-only (no deployment, no command execution)

## Verification

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes
- [ ] `npm run build` passes
- [ ] `node scripts/scan-build-artifacts.mjs packages/web/dist` passes
