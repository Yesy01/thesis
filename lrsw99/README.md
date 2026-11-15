# LRSW99 practical pseudonym system

This Python simulation follows Section 4 of Lysyanskaya, Rivest, Sahai, and
Wolf, *Pseudonym Systems*. The bundled group parameters are **INSECURE FOR REAL
CRYPTOGRAPHY**. Verbose traces intentionally reveal toy secrets and protocol
randomness so the algebra can be checked by hand.

## Browser demo

[Open the LRSW99 demo](https://yesy01.github.io/thesis/). The published app
runs the same Python backend in the browser with Stlite.

To prepare an updated deployment, run `python build_pages.py /tmp/lrsw99-pages`
from this directory and publish that output to the root of the `gh-pages`
branch.

## Run

From the `lrsw99` directory with Python 3.10 or later:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
pytest -q
python demos/demo_full_protocol.py
```

The protocol backend uses the standard library. Pytest runs the tests and
Streamlit runs the interactive walkthrough:

```sh
streamlit run app.py
```

In Setup, load the fixed demo group and generate keys for Alice, Bob, O, and
O′. Register Alice with both organizations, issue a credential from O, and
transfer it to O′. Register Bob with O′ to try the impersonation attack.
The Attack Demo also lets you modify a copy of Alice's credential or
substitute an issuer public key.
The focused demos are `python demos/demo_pi.py`,
`python demos/demo_extractor.py`, and `python demos/demo_gamma.py`.

## Campus demo

Open **Campus Demo** and click **Run Campus Demo**. The Registrar acts as
the CA, the Student Office issues passes, and the Library checks them.
The demo shows why a copied pass fails ownership and why proofs still pass
when a trusted Registrar or issuer knowingly certifies an ineligible user.
The campus enrollment rule and the example of joining records by campus
ID are application policy and metadata, respectively.

## Group parameters

Setup loads preselected constants from `src/group.py`. It does not search for
primes at runtime. The tests verify by trial division that
`q = 1,000,000,007` and `p = 44q + 1 = 44,000,000,309` are prime. They also
check `g = 2^44 mod p = 36,185,921,125`, `g != 1`, and `g^q mod p = 1`.
Since q is prime, the only possible nonidentity order dividing q is q.

## Protocol flow

An ordinary organization receives a randomized initial pair and supplies its
own exponent to form the registered pseudonym `(a,b)`. The CA receives the
initial pair `(g,g^x)`, which intentionally links enrollment to the master
public key. The same user can authenticate under distinct organization nyms
by proving knowledge of the common exponent `x`.

After the issuer authenticates the user's nym, `issue_credential` simulates the
issuer sending `A = b^s2` and `B = (a*A)^s1`. The user blinds both relations
with the same `gamma`, so `(a*A)^gamma = a^gamma * A^gamma` in the group. If
`a*A` happens to be the identity, `B` is also the identity and the second
equation remains valid. At transfer, the receiver checks both blinded proofs
against the issuer's public key, then runs interactive Π across the credential
nym and the receiver's registered nym.

The parties are simulated in one process. The caller supplies authenticated
issuer nyms and trusted issuer public keys. This is the **one-time** Section
4.3 credential. Reusing the same credential tuple makes presentations
linkable. Section 4.4 describes a separate multiple-use construction where
the issuer cooperates with the receiver to confirm credential validity.

## Γ algebra

The verifier computes `A' = A g^alpha h^beta`. Since `A = g^r` and
`h = g^x`, the effective nonce is `r' = r + alpha + beta*x mod q` and
`A' = g^r'`. The second commitment is `B' = (g_tilde^gamma)^r'`.
With `c = H(A',B') + beta mod q`, the blinded response becomes
`y' = y + alpha = r + (H(A',B') + beta)*x + alpha = r' + H(A',B')*x mod q`.
Verification therefore uses the ordinary Π_NI equations for the transformed
second pair.

## Security assumptions

Section 4 works in a group where discrete logarithms and Diffie–Hellman
problems are assumed hard. The practical one-time construction relies on DDH,
the security of interactive Chaum–Pedersen Π, a random oracle, and the
additional hardness assumption in Section 4.3, Problem 1. In Problem 1, given
`g^x` and `g^y` and oracle triples `(a, a^(s*y), a^(x+s*x*y))` for queried
`s` and fresh random bases `a`, the goal is to produce a valid triple for a
fresh nonzero query and a nonidentity base.

SHA-256 reduced modulo `q` models the paper's `H(A,B)` for this simulation.
The challenge hashes only the commitments, so it does not bind the public
statement. Test results verify the simulated algebra and specific rejection
cases. Computational unlinkability and the paper's hardness assumptions
remain outside what the toy group and tests can establish.

## Mapping the Code to LRSW Section 4

| Paper object | Code object |
| --- | --- |
| Π | `src/chaum_pedersen.py` |
| Π_NI | `prove_pi_ni` / `verify_pi_ni` |
| Γ | `src/gamma.py` |
| master secret x | `User.master_secret` |
| nym (a,b) | `Pseudonym` |
| (s1,s2) | `OrganizationCredentialKey` |
| T1,T2 | `GammaTranscript` |
| C_U,O | `Credential` |
