# Coconut implementation walkthrough

The main path is
`coconut/scheme.py`. The `scheme_up.py` variant is separate and is not used by
the educational trace.

The paper writes the source groups multiplicatively. `bplib` exposes G1 and G2
with additive Python operators, so the translation used throughout is:

| Paper notation | Python notation |
| --- | --- |
| `g^a` | `a * g` |
| `g h` in G1 or G2 | `g + h` |
| `g / h` | `g - h` |
| `e(g1, g2)` in GT | `G.pair(g1, g2)` |

## 1. G1, G2, GT, and the pairing

**Paper equation**

`e : G1 × G2 -> GT`, with prime group order `p` and generators `g1`, `g2`.

**Corresponding code**

`coconut.scheme.setup(q)` constructs `bplib.bp.BpGroup()`, obtains `gen1()`
and `gen2()`, and returns `G.pair` and `G.order()`. G1 values are represented by
`G1Elem`, G2 values by `G2Elem`, and pairing results by bplib's GT element. The
curve and pairing parameters come entirely from the unmodified bplib 0.0.6
`BpGroup` default.

**Corresponding tests**

- `tests/test_coconut.py::test_threshold_authority` exercises all three groups
  and the final pairing.
- `examples/trace_coconut.py` asserts the credential and showing pairing
  equations explicitly.

## 2. Hashing the commitment into G1

**Paper equation**

`h = H(c_m)`, where `H` maps the serialized commitment to G1.

**Corresponding code**

`prepare_blind_sign` computes the commitment as

`cm = r*g1 + sum(m_i*h_i)`

and then calls `G.hashG1(cm.export())`. The commitment's exported bytes are the
hash input. `blind_sign` independently recomputes the same value before
issuance. The implementation does not replace this with another hash-to-curve
construction.

**Corresponding tests**

- `tests/test_coconut.py` reaches the hash independently on the user and
  authority paths.
- `examples/trace_coconut.py` recomputes `h` from `cm.export()` and checks every
  unblinded share uses that `h`.

## 3. Shamir shares `x_i` and `y_i`

**Paper equation**

For threshold `t`, choose degree-`t-1` polynomials `v` and `w_j`, then set

`x_i = v(i)` and `y_(i,j) = w_j(i)`.

**Corresponding code**

`ttp_keygen` samples `t` coefficients for `v` and for every attribute
polynomial `w_j`. `poly_eval` evaluates each polynomial at authority positions
`1..n`. Each secret share is `(x_i, [y_(i,1), ..., y_(i,q)])`; each verification
share is `(g2, x_i*g2, [y_(i,j)*g2])`.

This is trusted-dealer key generation. The repository does not implement the
distributed key-generation protocol mentioned by the paper.

**Corresponding tests**

- `tests/test_coconut.py::test_threshold_authority` uses 8-of-10 shares.
- `examples/trace_coconut.py` uses 2-of-3 and, only under
  `--debug-secrets`, prints the selected `x_i`, `y_i`, and their interpolated
  values.

## 4. ElGamal encryption

**Paper equation**

For `gamma = d*g1`, encrypt the encoded private attribute `m*h` as

`c = (a,b) = (k*g1, k*gamma + m*h)`.

**Corresponding code**

`coconut.utils.elgamal_keygen` samples `d` and returns `(d, d*g1)`.
`elgamal_enc` samples `k` and returns `(a,b,k)`. The public request keeps only
`(a,b)`; `k` is passed into the issuance proof constructor as a witness.

**Corresponding tests**

- Both original tests in `tests/test_coconut.py` execute key generation and
  encryption.
- `examples/trace_coconut.py` checks that one ciphertext and a valid issuance
  proof were produced.

## 5. BlindSign's homomorphic transformation

**Paper equation**

For authority share `(x_i,y_i)` and ciphertext `(a,b)`, the single-attribute
form is

`c_tilde_i = (y_i*a, x_i*h + y_i*b)`.

After unblinding, this yields `s_i = (x_i + y_i*m)*h` in the library's additive
notation.

**Corresponding code**

`blind_sign` first calls `verify_pi_s`. It computes

- `t2 = sum(y_i*a_i)` for encrypted private attributes;
- `t1 = [m_j*h]` for public attributes; and
- `t3 = x_i*h + sum(y_i*b_i)` across encrypted and public encodings.

It returns `(h, (t2,t3))`, the blinded partial credential.

**Corresponding tests**

- `tests/test_coconut.py` exercises BlindSign in threshold and independent
  multi-authority modes.
- `examples/trace_coconut.py` explicitly verifies the issuance proof before
  each of two authority calls.

## 6. Unblind

**Paper equation**

`s_i = t3 - d*t2`, corresponding to division by the ElGamal factor in the
paper's multiplicative notation.

Substitution gives

`s_i = x_i*h + y_i*(k*gamma + m*h) - d*(y_i*k*g1)`

`    = (x_i + y_i*m)*h`, because `gamma = d*g1`.

**Corresponding code**

`unblind` passes the blinded pair to `elgamal_dec`, which returns `b - d*a`.

**Corresponding tests**

- `examples/trace_coconut.py` asserts
  `share_s == (x_i + y_i*m)*h` for both selected authorities.
- `tests/test_educational_flow.py::test_corrupted_credential_share_is_rejected`
  alters an unblinded share and observes rejection later.

## 7. Lagrange coefficients

**Paper equation**

For selected authority indexes `I`, interpolation at zero uses

`l_i = product((0-j)/(i-j)) mod p` for `j in I`, `j != i`.

**Corresponding code**

`coconut.utils.lagrange_basis(indexes, o, x=0)` computes the numerator and
denominator modulo the group order and calls petlib `Bn.mod_inverse` on the
denominator. Authority positions are one-based and are preserved through
`None` entries in the ordered key/share lists.

There is an existing edge defect: for a one-element index set the denominator
stays a Python integer, so `mod_inverse` is unavailable. The educational code
documents this; it does not alter the helper.

**Corresponding tests**

- `tests/test_coconut.py::test_threshold_authority` omits selected shares while
  preserving their positions.
- `tests/test_educational_flow.py::test_fewer_than_threshold_shares_fail_against_threshold_key`
  records the single-index defect and then shows that one partial credential
  fails against the consolidated threshold key.

## 8. AggCred in the exponent

**Paper equation**

`sigma = (h, product(s_i^l_i))`.

In additive source-group notation this is

`s = sum(l_i*s_i) = (x + sum(y_j*m_j))*h`.

**Corresponding code**

`agg_cred` filters `None` shares, computes coefficients for their original
one-based indexes, and calls `ec_sum([l_i*s_i])`. It takes `h` from the first
remaining partial credential. `agg_key` applies the same coefficients to the
G2 verification-key shares.

**Corresponding tests**

- `examples/trace_coconut.py` independently recomputes the weighted group sum,
  reconstructs `x` and `y` from the two selected shares, and asserts the final
  credential equation.
- The corrupted-share negative test confirms that an altered term does not
  produce a valid consolidated credential.

## 9. Credential re-randomization

**Paper equation**

For random nonzero-looking scalar `r'` sampled by the implementation,

`sigma' = (h',s') = (r'*h, r'*s)`.

**Corresponding code**

`prove_cred` samples `r_prime = o.random()` and computes both scalar
multiplications. It then samples another scalar `r`, constructs `kappa` and
`nu`, and produces the showing proof.

The API does not return `r_prime`, so external educational code cannot directly
assert the hidden scalar equality without intercepting randomness. Instead,
the trace verifies that both the original and randomized credentials satisfy
the same signature pairing relation. This demonstrates preservation of the
credential equation without extracting a discrete logarithm.

**Corresponding tests**

- `examples/trace_coconut.py` checks `sigma' != sigma` and verifies the
  randomized signature pairing.
- `tests/test_educational_flow.py::test_independently_altered_randomized_component_is_rejected`
  changes only `h'` and observes rejection.

## 10. Non-interactive proofs

**Paper equation**

Issuance uses a proof `pi_s` relating the commitment, encrypted private
attributes, public attributes, and encryption randomness. Showing uses `pi_v`
to prove knowledge of private attributes and the blinding scalar used in
`kappa` and `nu`.

**Corresponding code**

`coconut.proofs.make_pi_s` and `make_pi_v` implement Schnorr-style witness
commitments and responses. `to_challenge` serializes the listed group elements,
joins their hexadecimal encodings, hashes with SHA-256, and interprets the
digest as a petlib `Bn`. Verification reconstructs the witness commitments and
recomputes the challenge.

The implementation provides fixed equality relations. It does not implement
the paper's generic application predicates `phi` or `phi'`. Also, invalid
proofs reach `assert` statements in `blind_sign` and `verify_cred`; callers may
therefore receive `AssertionError` rather than a Boolean `False`.

**Corresponding tests**

- `tests/test_educational_flow.py::test_malformed_showing_proof_is_rejected`
  changes the Fiat--Shamir challenge and accepts the assertion as rejection.
- `examples/trace_coconut.py` directly invokes both proof verifiers before the
  enclosing protocol functions.

## 11. VerifyCred and the pairing equation

**Paper equation**

The showing values are

`kappa = alpha + sum(beta_i*m_i) + r*g2`

and `nu = r*h'`. Verification checks

`e(h', kappa + disclosed_public_terms) = e(s' + nu, g2)`.

**Corresponding code**

`verify_cred` first verifies `pi_v`. It determines the number of hidden
attributes from the proof response vector, places supplied public attributes
after them in the verification-key `beta` vector, rejects an infinite `h`, and
evaluates the pairing equality. It returns the Boolean result of the final
equation when proof verification reaches that point.

**Corresponding tests**

- `examples/trace_coconut.py` asserts the exact pairing equation and then calls
  `verify_cred`.
- `tests/test_educational_flow.py` covers changed private attributes, too few
  shares, corrupted shares, malformed proofs, wrong verification keys, and an
  independently altered randomized component.

## End-to-end execution map

| Paper protocol | Code execution | Baseline test |
| --- | --- | --- |
| Setup | `setup(1)` | `test_threshold_authority` |
| TTPKeyGen | `ttp_keygen(params, 2, 3)` | `test_threshold_authority` |
| AggKey | `agg_key(params, ordered_vks)` | both `test_coconut.py` tests |
| PrepareBlindSign | `elgamal_keygen`; `prepare_blind_sign` | both `test_coconut.py` tests |
| BlindSign | two calls to `blind_sign` | both `test_coconut.py` tests |
| Unblind | two calls to `unblind` | both `test_coconut.py` tests |
| AggCred | `agg_cred` with ordered shares | both `test_coconut.py` tests |
| ProveCred | `prove_cred` | all original end-to-end tests |
| VerifyCred | `verify_cred` | all original end-to-end tests |

The runnable 2-of-3 version of this map is `examples/trace_coconut.py`.
