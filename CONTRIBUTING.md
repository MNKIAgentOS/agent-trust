# Contributing

- Every behavioural change to the verifier ships with a conformance vector first (`conformance/`), and
  both runners (TypeScript `npm test`, Go `cd go && go test ./...`) must pass.
- The verifier stays pure: no network, no clock other than the injected one, no framework imports.
- Sign off your commits (Developer Certificate of Origin, `git commit -s`). Contributions are licensed
  under Apache-2.0.
- Security issues: see SECURITY.md — never in a public issue.
