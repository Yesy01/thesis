# Coconut reproduction notes

This file records the baseline environment, setup failures, compatibility
changes, and the mapping between the implementation and the Coconut paper.

## Baseline source

- Repository: `https://github.com/asonnino/coconut`
- Commit: `d45b1426e5aeba16c43abdd99a3ee5726edcd19e`
- Package version: `coconut-lib 1.3.1`
- Original cryptographic library code has not been modified.


The combined suite contains 9 passing tests. The Phase 8 nullifier is
intentionally not implemented; the requested ZK-binding TODO remains explicit.

##  implementation map

The main implementation is `coconut/scheme.py`. Supporting Fiat--Shamir
proofs are in `coconut/proofs.py`; ElGamal and interpolation helpers are in
`coconut/utils.py`. `coconut/scheme_up.py` is a separate unconditional-privacy
variant.

| Paper protocol | Python implementation |
| --- | --- |
| Setup | `coconut.scheme.setup` |
| KeyGen | `coconut.scheme.keygen` |
| TTPKeyGen | `coconut.scheme.ttp_keygen` |
| AggKey | `coconut.scheme.agg_key` |
| PrepareBlindSign | `coconut.utils.elgamal_keygen` and `coconut.scheme.prepare_blind_sign` |
| BlindSign | `coconut.scheme.blind_sign` |
| Unblind | `coconut.scheme.unblind` |
| AggCred | `coconut.scheme.agg_cred` |
| ProveCred | `coconut.scheme.prove_cred` |
| VerifyCred | `coconut.scheme.verify_cred` |

## isolated environment


## Compatibility changes

- Added `Dockerfile.repro` and `.dockerignore`; these are setup-only files.
- Used Python 3.8.20 on Debian Bullseye under `linux/amd64`.
- Installed the releases selected by the repository's unpinned requirements:
  petlib 0.0.45 and bplib 0.0.6.
- Installed petlib and bplib sequentially to avoid bplib's legacy
  `setup_requires` recursion observed during the original installation attempt.
- Pointed APT at Debian's official Bullseye archive after Bullseye LTS ended
  and disabled the archive metadata expiry check.
- Did not patch Coconut, petlib, bplib, their curves, pairing groups, proof
  algorithms, or credential algorithms.


Final verification on Python 3.8.20 completed successfully:

```text
pytest -v --cov=coconut tests/: 9 passed, 96% coconut coverage
examples/trace_coconut.py: credential accepted = True
python -m ashoka_demo.demo: credential accepted = True
```

`git diff -- coconut` is empty: none of the original cryptographic library
files were modified.

## original test baseline

The original test files were run before adding educational tests:

```text
tests/test_coconut.py::test_threshold_authority PASSED
tests/test_coconut.py::test_multi_authority PASSED
tests/test_coconut_up.py::test_multi_authority PASSED
3 passed
```

This established a working original baseline. The existing
`test_coconut_up.py` still calls `verify_cred` without asserting its returned
Boolean; this was documented but not changed.

## educational credential trace

`examples/trace_coconut.py` executes a 2-of-3 credential with one private
attribute. It prints protocol stages without secrets by default:

1. pairing-group setup;
2. threshold TTP key generation and verification-key aggregation;
3. commitment, `H(cm)`, ElGamal encryption, and issuance proof;
4. blind issuance by authorities 1 and 2;
5. unblinding of both partial credentials;
6. credential aggregation;
7. credential randomization and showing proof; and
8. proof and pairing verification.

The trace asserts:

- `s_i = (x_i + y_i*m)h` for each selected partial credential;
- the Lagrange-weighted group sum used by `AggCred`;
- `s = (x + y*m)h` after reconstructing `x` and `y` from shares;
- the signature pairing before and after randomization;
- both issuance and showing proof verification; and
- `e(h', kappa) = e(s' + nu, g2)`.

The implementation does not expose the randomization scalar `r'`. The trace
therefore checks preservation of the signature pairing instead of attempting
to extract a discrete logarithm or intercept library randomness.

`--debug-secrets` optionally prints `m`, the user's ElGamal secret, authority
`x_i`/`y_i` shares, Lagrange coefficients, and reconstructed scalars. The mode
is labelled as local educational output that must not be used in production.

##  negative tests

`tests/test_educational_flow.py` verifies rejection for:

1. a changed private attribute;
2. fewer than the threshold number of valid credential shares;
3. a corrupted partial credential;
4. a malformed showing proof;
5. the wrong consolidated verification key; and
6. an independently altered randomized credential component.

The original API sometimes signals invalid proofs with `AssertionError` rather
than returning `False`. The educational helper normalizes either result to a
rejection for test purposes. All six cases pass.


## isolated Ashoka simulation

`ashoka_demo/demo.py` remains separate from the original Coconut package. It
simulates:

- three credential authorities with threshold two;
- one randomly sampled private student secret `k`;
- one public `IssueID`;
- one complaint;
- blind issuance and aggregation;
- a randomized Coconut credential showing; and
- an in-memory local `UsedList` record after successful verification.

The local record is not presented as anonymous double-use prevention. Both the
code and `ashoka_demo/README.md` retain:

```text
TODO: application-specific construction requiring ZK binding to credential
secret k.
```

## Files added

- `.dockerignore`
- `Dockerfile.repro`
- `NOTES.md`
- `IMPLEMENTATION_WALKTHROUGH.md`
- `examples/trace_coconut.py`
- `tests/test_educational_flow.py`
- `ashoka_demo/__init__.py`
- `ashoka_demo/demo.py`
- `ashoka_demo/README.md`

## Commands from a fresh terminal

```console
cd /Users/yesie/Downloads/repos/thesis/coconut
open -a Docker
docker build --progress=plain --platform linux/amd64 \
  --file Dockerfile.repro --tag coconut-repro:py38 .
```

Run the complete suite:

```console
docker run --rm --platform linux/amd64 \
  --volume "$PWD:/workspace" --workdir /workspace \
  --env PYTHONPATH=/workspace --env PYTHONDONTWRITEBYTECODE=1 \
  coconut-repro:py38 \
  /opt/coconut-venv/bin/pytest -v --cov=coconut tests/
```

Run the trace and application demo:

```console
docker run --rm --platform linux/amd64 \
  --volume "$PWD:/workspace" --workdir /workspace \
  --env PYTHONPATH=/workspace \
  coconut-repro:py38 \
  /opt/coconut-venv/bin/python examples/trace_coconut.py

docker run --rm --platform linux/amd64 \
  --volume "$PWD:/workspace" --workdir /workspace \
  --env PYTHONPATH=/workspace \
  coconut-repro:py38 \
  /opt/coconut-venv/bin/python -m ashoka_demo.demo
```

## Unresolved issues and boundaries

- `lagrange_basis` raises `AttributeError` for a one-element index set because
  its denominator remains a Python `int`. The original library was not patched.
- Invalid proof handling relies on Python `assert` in the original library.
- Generic application predicates `phi` and `phi'` from the paper are not
  implemented by this repository.
- The `scheme_up` test does not assert the result returned by `verify_cred`.
- The Ashoka `UsedList` has no credential-bound nullifier; implementing one
  requires an application-specific ZK construction.
- Debian Bullseye is archived, and the `linux/amd64` image runs through
  emulation on this Apple Silicon host.
