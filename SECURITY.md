# Security Policy

Agent Control Verification is pre-alpha security research software.

## Safe-use boundary

The project is designed for systems you own or are explicitly authorized to test. The default test suite uses synthetic local effects only.

Do not use this project to:

- attack systems without authorization;
- collect or exfiltrate real credentials;
- scan third-party infrastructure without permission;
- bypass access controls on systems you do not own;
- send real emails, payments, transactions, or destructive commands from the default test suite.

## Reporting a vulnerability

For non-sensitive bugs, open a GitHub issue.

For a vulnerability that would expose secrets or create a practical bypass, avoid publishing exploit details in a public issue. Contact the repository maintainer through the GitHub profile until private vulnerability reporting is configured.

A report should include the affected commit/version, minimal reproduction, expected behavior, actual behavior, and whether the issue can cause a false PASS.
