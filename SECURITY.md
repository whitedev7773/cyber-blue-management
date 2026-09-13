# Security scope

Aegis Review 0.1 is a loopback-only, single-user configuration review MVP. It is not an assurance that a project is secure.

Uploaded code is never executed. Archives are read in memory under explicit limits. All displayed uploaded strings use DOM text nodes. Raw configuration contents are not persisted. Report metadata may include sensitive filenames or rule identifiers.

Do not expose the development server through a public reverse proxy or port-forward. Local processes using the same account are inside the trust boundary. The local API token is a cross-origin mutation defense, not a multi-user identity system.

Use private reports for suspected issues; do not include real credentials or private source files in public issues. There is no production support or response-time commitment in this MVP.
