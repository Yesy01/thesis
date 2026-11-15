# Coconut reproduction notes

This file records the baseline environment, setup failures, compatibility
changes, and the mapping between the implementation and the Coconut paper.

## Baseline source

- Repository: `https://github.com/asonnino/coconut`
- Commit: `d45b1426e5aeba16c43abdd99a3ee5726edcd19e`
- Package version: `coconut-lib 1.3.1`
- Original cryptographic library code has not been modified.


The combined suite contains 14 passing tests. The Phase 8 nullifier is
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
pytest -v --cov=coconut tests/: 14 passed, 96% coconut coverage
examples/trace_coconut.py: credential accepted = True
python -m ashoka_demo.demo: credential accepted = True
GUI POST /api/run/stream: 18 ordered start/complete events, credential accepted = True
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

## educational GUI

The application layer now has a dependency-free browser interface:

- `ashoka_demo/protocol.py` contains the reusable application flow and calls
  the original functions in `coconut/scheme.py` directly;
- `ashoka_demo/web.py` exposes the flow through a local standard-library HTTP
  server;
- `ashoka_demo/static/` contains the HTML, CSS, and JavaScript interface; and
- `tests/test_ashoka_demo.py` verifies a complete real protocol run, the
  application-only duplicate record behavior, and input validation.

The GUI displays the paper algorithm, Python function, source file, stage
result, and local duration. It never serializes the private student secret,
ElGamal private key, authority secret shares, credential group elements, or
proof responses. `IssueID` is the only displayed input included as a public
credential attribute. Complaint ID and complaint text remain application data.

This is new educational code. The original `coconut/` package is unchanged.
The interface does not add a cryptographic nullifier and repeats the existing
UsedList limitation in its result and security-boundary panel.

The local server also exposes `POST /api/run/stream`. `execute_flow` calls an
optional event callback immediately before and after each of its nine real
operations, and the HTTP handler flushes those 18 events as newline-delimited
JSON. The GUI marks the current actor and function as running, then replaces
that state with the measured result. Its short visual delay is presentation
pacing only; the duration shown beside each operation is measured around the
underlying Python call and excludes that delay.

### GitHub Pages browser build

`ashoka_demo/build_pages.py` creates the static build published at
`https://yesy01.github.io/thesis/coconut/`. The build executes the repository's
Python protocol and proof code in Pyodide. A Web Worker forwards the same 18
ordered stage events to the interface while keeping the browser responsive.

GitHub Pages cannot load the native petlib/bplib extension stack used by the
Docker reproduction. The browser-only `ashoka_demo/browser/pairing.py` adapter
therefore uses noble-curves BLS12-381 group and pairing operations, whose curve
parameters and encodings differ from native bplib. This compatibility boundary
is displayed on the hosted page and documented in `ashoka_demo/README.md`.
The Docker environment remains the reference environment for reproducing the
original implementation; the hosted build is an educational visualization.

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
- `ashoka_demo/protocol.py`
- `ashoka_demo/web.py`
- `ashoka_demo/static/index.html`
- `ashoka_demo/static/styles.css`
- `ashoka_demo/static/app.js`
- `tests/test_ashoka_demo.py`

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
