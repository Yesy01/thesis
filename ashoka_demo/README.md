# Ashoka demo

This directory is an application simulation layered on the unmodified Coconut
library. It creates three authority shares with a threshold of two, issues a
credential containing a private student secret `k` and public `IssueID`, shows
a randomized credential, verifies it, and records one complaint in an
in-memory `UsedList`.

The `UsedList` key is only a local complaint record. It is not anonymous and is
not cryptographically bound to the Coconut credential.

> TODO: application-specific construction requiring ZK binding to credential
> secret `k`.

Run from the repository root inside the reproduction environment:

```console
python -m ashoka_demo.demo
```
