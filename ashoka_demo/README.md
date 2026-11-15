# Ashoka demo

This directory is an application simulation layered on the unmodified Coconut
library. It creates three authority shares with a threshold of two, issues a
credential containing a private student secret `k` and public `IssueID`, shows
a randomized credential, verifies it, and records one complaint in an
in-memory `UsedList`.

The browser interface calls the same reusable flow in `protocol.py` and shows
the paper algorithm, original Python function, source file, outcome, and local
duration for every stage. It uses Python's standard-library HTTP server and
adds no framework or cryptographic dependency.

The `UsedList` key is only a local complaint record. It is not anonymous and is
not cryptographically bound to the Coconut credential.

> TODO: application-specific construction requiring ZK binding to credential
> secret `k`.

## GitHub Pages

[Open the Coconut Protocol Lab](https://yesy01.github.io/thesis/coconut/).

The hosted page runs the original Python protocol and proofs in Pyodide.
Its browser adapter uses noble-curves for BLS12-381 group operations. The
native Python demo uses bplib and petlib with different curve parameters
and encodings. A Web Worker emits each protocol stage while Python runs so
the interface remains responsive. The browser tab keeps its own complaint
list until reload.

To build the page from the Coconut project directory:

```sh
python ashoka_demo/build_pages.py /tmp/thesis-pages/coconut
```

Publish that output in the `coconut/` directory on `gh-pages`.

Run from the repository root inside the reproduction environment:

```console
python -m ashoka_demo.demo
```

Run the GUI from the repository root inside the reproduction environment:

```console
python -m ashoka_demo.web --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000`. With Docker, publish port 8000:

```console
docker run --rm --platform linux/amd64 \
  --publish 8000:8000 \
  --volume "$PWD:/workspace" --workdir /workspace \
  --env PYTHONPATH=/workspace \
  coconut-repro:py38 \
  /opt/coconut-venv/bin/python -m ashoka_demo.web \
  --host 0.0.0.0 --port 8000
```

The GUI does not display the private student secret or authority secret-key
shares. Complaint ID and complaint text stay in the application layer; they
are not attributes in the Coconut credential.
