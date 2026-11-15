from pathlib import Path
import sys

# Allow direct execution as well as python -m demos.demo_...
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.chaum_pedersen import (
    PiTranscript,
    extract_witness,
    pi_prover_commit,
    pi_prover_response,
    pi_verify,
)
from src.group import DEMO_PARAMS, modexp


def main() -> None:
    params = DEMO_PARAMS
    g, p, q = params.g, params.p, params.q
    x = 42
    g_tilde = modexp(g, 9, p)
    h, h_tilde = modexp(g, x, p), modexp(g_tilde, x, p)
    commitment, r = pi_prover_commit(g, g_tilde, params)

    # Deliberately reuse the commitment to exhibit special soundness.
    c1, c2 = 3, 11
    y1, y2 = pi_prover_response(r, c1, x, q), pi_prover_response(r, c2, x, q)
    print("Two challenges for the same Π commitment")
    for c, y in ((c1, y1), (c2, y2)):
        proof = PiTranscript(commitment.A, commitment.B, c, y)
        valid = pi_verify(g, h, g_tilde, h_tilde, proof, params, verbose=True)
        assert valid

    extracted_x = extract_witness(c1, y1, c2, y2, q)
    print(f"  (y1 - y2) * (c1 - c2)^(-1) mod q = {extracted_x}")
    print(f"  Extracted x equals actual x ({x}): {extracted_x == x}")
    assert extracted_x == x


if __name__ == "__main__":
    main()
