# Scenarios

This directory will hold portable security-property scenarios once the result/evidence schema stabilizes.

The first scenarios are currently encoded directly in deterministic unit tests so the project does not freeze a public scenario format prematurely.

Planned scenario families:

- deny prevents side effect;
- allow binds exact action;
- approval binding;
- approval replay;
- control unavailable / timeout;
- audit completeness;
- identity scope;
- tool scope;
- canary-secret boundary;
- competing-hook composition.
