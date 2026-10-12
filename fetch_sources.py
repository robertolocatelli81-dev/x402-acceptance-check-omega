# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Download the third-party inputs into fonti/ and check each against a pinned sha256.
They are not redistributed in this repository: the vectors and README belong to
babyblueviper1/preaction-governance-conformance (vectors CC0-1.0, repository MIT), the RFCs and the draft to
the IETF Trust and their authors. Exit 0 iff every file matches its pin."""
import hashlib
import os
import sys
import urllib.request

BBV = "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/%s/examples/acceptance-record-cold/vectors.json"
BBR = "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/%s/examples/acceptance-record-cold/README.md"
PINS = [
    ("d750291_vectors.json", BBV % "d750291d9f06fe26455196efed748388f9f46adb",
     "4d01f3e72bdcbcca9e3e2a883ced0a87ae6c969f5cf6de4ef754dc63eb8ced0e"),
    ("646588c_vectors.json", BBV % "646588cbab5e3cfe0824af6bb83ee1779f0f67ee",
     "c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0"),
    ("5a4ea06_vectors.json", BBV % "5a4ea06dff481d6666f072c83c582f5fb29d99de",
     "c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0"),
    ("5a4ea06_README.md", BBR % "5a4ea06dff481d6666f072c83c582f5fb29d99de",
     "9c1b7a7463a7350486d0ccfaa638cd4b8077f027b93280f8f058a5898cc3d419"),
    ("646588c_README.md", BBR % "646588cbab5e3cfe0824af6bb83ee1779f0f67ee",
     "f7731aa1f0670e8a5c897d538edb717ff848fcc05ad65537d95c9ff5d99ebd4a"),
    ("90b5032_README.md", BBR % "90b5032e0ce8de9400c738fbb1cb2a88f638a129",
     "7574b1c926f1dc50f766a6becce7db05f8925c2f626a04fe6f4f86788893edf1"),
    ("rfc7515.txt", "https://www.rfc-editor.org/rfc/rfc7515.txt",
     "ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40"),
    ("rfc8032.txt", "https://www.rfc-editor.org/rfc/rfc8032.txt",
     "ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3"),
    ("draft-krausz-verification-state-03.txt", "https://www.ietf.org/archive/id/draft-krausz-verification-state-03.txt",
     "1d142b3effbfc612dca388567902f63823b45dcf69eece423e6b2b9a28dcbed9"),
]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(here, "fonti"), exist_ok=True)
    bad = 0
    for name, url, pin in PINS:
        path = os.path.join(here, "fonti", name)
        if not os.path.exists(path):
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
            with open(path + ".part", "wb") as f:
                f.write(data)
            os.replace(path + ".part", path)
        with open(path, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        ok = got == pin
        bad += not ok
        print("%-42s %s" % (name, "sha256 ok" if ok else "SHA256 MISMATCH " + got))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
