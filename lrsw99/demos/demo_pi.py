from pathlib import Path
import sys

# Allow direct execution as well as python -m demos.demo_...
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.chaum_pedersen import prove_pi_ni, run_pi, verify_pi_ni
from src.group import DEMO_PARAMS, modexp


def main() -> None:
    params = DEMO_PARAMS
    g, p = params.g, params.p
    x = 23
    g_tilde = modexp(g, 7, p)
    h, h_tilde = modexp(g, x, p), modexp(g_tilde, x, p)
    print("Interactive Π completeness")
    print(f"  x = {x}, h = g^x, h_tilde = g_tilde^x")
    _, valid = run_pi(g, h, g_tilde, h_tilde, x, params, verbose=True)
    assert valid

    print("\nNon-interactive Π_NI")
    transcript = prove_pi_ni(g, g_tilde, x, params)
    valid = verify_pi_ni(g, h, g_tilde, h_tilde, transcript, params, verbose=True)
    assert valid


if __name__ == "__main__":
    main()
