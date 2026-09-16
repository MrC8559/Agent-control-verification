# AGENTS.md

This repository tests security controls, so development discipline is part of the product.

## Core invariants

1. **Never convert missing evidence into PASS.** Use `INCONCLUSIVE`.
2. **Verify effects independently of control claims** wherever the environment permits.
3. **Bind authorization to the exact action**: identity, tool, target, and arguments.
4. **Keep tests deterministic first.** Model-dependent attacks belong on top of deterministic primitives, not underneath them.
5. **Default to synthetic/local effects.** CI must never require production credentials or perform consequential external actions.
6. **Preserve vulnerable fixtures.** They are controls proving that the verifier can fail.
7. **Do not claim certification or standards conformance** unless an external process actually establishes it.
8. **Version evidence.** Real-host reports must record exact host, adapter, policy, and runtime versions.
9. **Minimize secrets.** Test canaries must be synthetic and safe to publish.
10. **Prefer falsifiable properties to security scores.**

## Code style

- Python 3.11+ standard library by default.
- Small typed dataclasses and pure verification functions.
- Tests use `unittest` until a dependency provides clear value.
- Security properties should return structured evidence, not only booleans.
- Add a regression test for every fixed verification bug.

## Research discipline

When adding a competitor, standard, or external claim to research notes:

- prefer primary sources;
- record the date checked;
- distinguish shipped behavior from roadmap claims;
- state overlap honestly;
- change the project thesis if evidence falsifies it.

## Pull requests

Keep PRs narrow. Explain:

- which security property changes;
- what evidence demonstrates the change;
- what remains untested;
- whether the threat model changed.
