from pathlib import Path
import sys

# Allow direct execution as well as python -m demos.demo_...
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.gamma import run_gamma
from src.group import DEMO_PARAMS, modexp, random_scalar


def main() -> None:
    params = DEMO_PARAMS
    g, p = params.g, params.p
    x = 17
    g_tilde = modexp(g, 13, p)
    h, h_tilde = modexp(g, x, p), modexp(g_tilde, x, p)
    gamma = random_scalar(params.q, nonzero=True)
    print(f"Γ blinding for a statement with witness x = {x}")
    proof = run_gamma(g, h, g_tilde, h_tilde, x, gamma, params, verbose=True)
    print(f"  Blinded transcript = {proof}")


if __name__ == "__main__":
    main()
