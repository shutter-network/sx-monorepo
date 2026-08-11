#!/usr/bin/env python3
"""Cross-language gate: geg's Python must accept TS-minted ATTESTATION_V1.

The TypeScript side is verified against geg's canonical vectors by
`packages/private-vote-sdk/tests/geg-parity.test.ts` (Gate 0). That covers TS
*verifying* Python's output. This script covers the other direction — Python
*verifying* TypeScript's output — which is the direction that actually runs in
production once hub mints the credentials geg's keypers consume.

Strictly, most of that direction is already implied: a Schnorr signature cannot
verify under a different message, so the vectors passing proves TS computes the
same digest as Python, and `signAttestation`/`verifyAttestationSig` share one
`attestationMessage` implementation. This script is the empirical confirmation of
a step that reasoning says must hold — cheap to run, and the thing you want after
touching `attestation.ts` or bumping the pinned geg version.

**Why it lives here and not in the SDK package.** `packages/private-vote-sdk` is
a vendored fork of an upstream repo; its value is being a clean mirror plus
minimal protocol-level deltas. sx-specific tooling that shells into a sibling
Python checkout does not belong inside that mirror, so it sits with the other
monorepo dev scripts. It is also a **dev-time** gate, never a CI gate: sx
deliberately carries no Python toolchain (decision D10).

    # 1. regenerate the fixture from TypeScript
    cd packages/private-vote-sdk
    WRITE_ATTESTATION_FIXTURE=1 npx jest tests/voting.attestation.test.ts

    # 2. verify it with geg (from the repo root)
    python3 scripts/geg/verify-attestation-fixture.py [path-to-geg-repo]

Exit code 0 means the two implementations agree.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FIXTURE = (
    REPO_ROOT
    / "packages"
    / "private-vote-sdk"
    / "tests"
    / "fixtures"
    / "ts-minted-attestations.json"
)
# Sibling-checkout layout used in development; override with the argument or GEG_REPO.
DEFAULT_GEG = REPO_ROOT.parent / "Munich_Voting" / "generalised-el-gamal"


def unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def main() -> int:
    geg_repo = Path(
        sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GEG_REPO", DEFAULT_GEG)
    ).resolve()
    venv_python = geg_repo / ".venv" / "bin" / "python"

    if not FIXTURE.exists():
        print(f"FAIL: no fixture at {FIXTURE}\n"
              f"      generate it with:\n"
              f"        cd packages/private-vote-sdk && \\\n"
              f"        WRITE_ATTESTATION_FIXTURE=1 npx jest tests/voting.attestation.test.ts",
              file=sys.stderr)
        return 2

    # Re-exec inside geg's venv so `import geg` resolves without polluting this
    # interpreter's environment.
    if os.environ.get("_GEG_REEXEC") != "1":
        if not venv_python.exists():
            print(f"FAIL: no geg venv at {venv_python}\n"
                  f"      pass the geg repo path or set GEG_REPO",
                  file=sys.stderr)
            return 2
        env = {**os.environ, "_GEG_REEXEC": "1"}
        return subprocess.call([str(venv_python), str(Path(__file__).resolve()),
                                str(geg_repo)], env=env)

    from geg.envelopes.types import Attestation, AttestationScheme
    from geg.ports.eligibility import verify_attestation

    fixture = json.loads(FIXTURE.read_text())
    elig_key = unhex(fixture["eligibilityKey"])

    schemes = {
        "ATTESTATION_V1": AttestationScheme.V1,
        "ATTESTATION_LEGACY": AttestationScheme.LEGACY,
    }

    failures = 0
    for case in fixture["cases"]:
        attestation = Attestation(
            election_id=unhex(case["electionId"]),
            pseudonym=unhex(case["pseudonym"]),
            vk=unhex(case["vk"]),
            weight=int(case["weight"]),
            signature=unhex(case["signature"]),
            scheme=schemes[case["scheme"]],
            nonce=int(case["nonce"]),
        )
        got = verify_attestation(
            elig_key,
            attestation,
            election_id=unhex(case["electionId"]),
            max_weight=int(case["maxWeight"]),
        )
        want = bool(case["expected"]["verify"])
        status = "ok" if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  [{status}] {case['name']}: verify={got} (expected {want})")

    n = len(fixture["cases"])
    if failures:
        print(f"\nFAIL: {failures}/{n} TS-minted attestations rejected by geg",
              file=sys.stderr)
        return 1
    print(f"\nPASS: geg accepts all {n} TS-minted ATTESTATION_V1 credentials")
    return 0


if __name__ == "__main__":
    sys.exit(main())
