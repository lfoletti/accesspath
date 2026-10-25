# Security policy

## Report a vulnerability

Do not open a public issue for a vulnerability. Use the private vulnerability reporting of GitHub (Security tab,
"Report a vulnerability") when it is available for this repository, or contact the maintainer through the address
on the GitHub profile of [@lfoletti](https://github.com/lfoletti).

Give the version or commit, the steps to reproduce, and the impact. You will receive an answer within one week.

## Scope

accesspath fetches untrusted web content and passes reports to AI agents. In scope, for example:

- a way for an audited site to make accesspath reach an internal address (SSRF), also after a redirect;
- content from an audited site that escapes the data markers of a report (prompt injection into the agent);
- a secret from `ACCESSPATH_SECRET_*` or from a HAR file written to disk or to a report;
- a path traversal when accesspath writes files named after site data.

Out of scope: the access policy of the audited sites themselves.

## Supported versions

Only the latest commit of `main` receives fixes.
