# Public Review Release

## Purpose of This Repository

This repository is being made publicly accessible for:

- Participation in the LBAMM public audit competition
- Technical review and evaluation

This release enables researchers and potential integrators to evaluate the architecture, interfaces, and extensibility of the protocol.

It is not being released for production deployment or live network use at this time.

---

## Vulnerability Reporting During Public Audit

All security findings for this repository during the official audit window (February 23, 2026 through April 9, 2026) must be submitted exclusively through the official Guardian Defender audit portal:

https://defender.guardianaudits.com/contests/6998a6cf6a508136784689d0

Do not open GitHub Issues or Pull Requests to report vulnerabilities.

Only submissions made through the Guardian Defender platform are eligible for consideration under the competition.

All submissions are considered confidential under the Guardian Bounty Contest Terms. Public disclosure of vulnerabilities prior to coordinated resolution is strictly prohibited and may result in disqualification and forfeiture of rewards.

---

## Evaluation Only – Not Production Ready

This repository represents an audit and review snapshot.

The code:

- May contain incomplete documentation
- May include experimental or evolving components
- Has not been finalized for production deployment
- Has not completed the full security lifecycle

You must not deploy this code to mainnet or production systems.

Evaluation, simulation, testing, and integration planning are permitted.  
Live deployment and commercial operation are not.

---

## Licensing

License terms are defined at the file level via SPDX identifiers.

Test files may not include SPDX identifiers and are provided for evaluation and research purposes.

Each file’s SPDX license identifier governs its permitted use.

Nothing in this release grants additional rights beyond those defined in the applicable licenses.

---

## Permitted Activities During Public Review

You may:
- Review and analyze the source code
- Run and extend tests locally
- Perform fuzzing and static analysis
- Build proof-of-concept integrations in local environments
- Conduct architectural evaluation for potential future integration

You may not:
- Deploy the protocol to production environments
- Launch public markets using this code
- Represent this release as production-ready infrastructure
- Circumvent or dilute license restrictions

---

## Tests vs Protocol Code

Test files are provided to aid understanding and security review.

They:
- Are not production components
- May omit SPDX identifiers
- Do not define license scope for the core protocol

Source files under `src/` and imported dependencies define the executable protocol logic and are governed by their respective licenses.

---

## No Warranty

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

Limit Break disclaims all warranties, express or implied, including merchantability, fitness for a particular purpose, and non infringement.

---

## Audit & Integration Information

Full contest scope, severity definitions, reward structure, and submission requirements are available on the Guardian Defender portal.

Builders and infrastructure partners may use this repository for technical diligence and integration planning during the public review phase.