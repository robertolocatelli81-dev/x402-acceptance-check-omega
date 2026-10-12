# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Mutants of the lines that write the receipt (exit 74, 2026-10-12), run against test_ricevuta.py: each mutant
is applied to a copy of this directory and is killed iff test_ricevuta.py exits non-zero there. The unmutated
copy must pass first (the bench must be able to pass), and each mutant's text must occur exactly once.

python3 mutanti_ricevuta.py   -> exit 0 iff the unmutated copy passes and every mutant is killed
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AC = "acceptance_check.py"
TEST = "test_ricevuta.py"

MUTANTS = [
    ("no flush of the receipt", "            data = data[n:]\n        out.flush()\n", "            data = data[n:]\n"),
    ("one write, short count ignored", "        while data:\n            n = out.write(data)\n",
     "        while data:\n            n = out.write(data) or len(data)\n            n = len(data)\n"),
    ("short write of 0/None not refused", "            if not n:\n                raise OSError(\"short write: %d bytes not written\" % len(data))\n", ""),
    ("receipt written through the text layer (as at c3e44ef)",
     "        out = sys.stdout.buffer\n", "        sys.stdout.write(text); sys.stdout.flush(); return\n"),
    ("write error not caught", "    except OSError as e:\n        _quiet_fd(1)\n",
     "    except ZeroDivisionError as e:\n        _quiet_fd(1)\n"),
    ("exit with the verdict when the receipt is lost", "        return EXIT_RECEIPT_NOT_WRITTEN\n",
     "        return rep[\"exit\"]\n"),
    ("exit 1 when the receipt is lost", "EXIT_RECEIPT_NOT_WRITTEN = 74", "EXIT_RECEIPT_NOT_WRITTEN = 1"),
    ("exit 0 when the receipt is lost", "EXIT_RECEIPT_NOT_WRITTEN = 74", "EXIT_RECEIPT_NOT_WRITTEN = 0"),
    ("stdout None not checked", "    if sys.stdout is None:\n        raise OSError(\"stdout is closed\")\n", ""),
    ("fd 1 left as it is after the failure", "        _quiet_fd(1)\n        _say(", "        _say("),
    ("no dup2 in _quiet_fd", "        os.dup2(null, fd)\n", ""),
    ("no stderr line", "        _say(\"receipt not written: %s\\n\" % e)\n", ""),
    ("stderr None not checked", "        if sys.stderr is None:\n            return\n", ""),
    ("stderr error not caught", "    except (OSError, ValueError):\n        _quiet_fd(2)\n",
     "    except ZeroDivisionError:\n        _quiet_fd(2)\n"),
    ("fd 2 left as it is after a stderr failure", "    except (OSError, ValueError):\n        _quiet_fd(2)\n",
     "    except (OSError, ValueError):\n        pass\n"),
    ("usage written without the guard", "        _say(\"usage: acceptance_check.py CASE.json\\n\")\n",
     "        sys.stderr.write(\"usage: acceptance_check.py CASE.json\\n\")\n"),
    ("ValueError of a closed stdout not converted", "    except ValueError as e:                                  # I/O",
     "    except ZeroDivisionError as e:                           # I/O"),
]


def copy_dir():
    d = tempfile.mkdtemp()
    for name in os.listdir(HERE):
        src = os.path.join(HERE, name)
        if name.endswith(".py"):
            shutil.copy(src, d)
        elif name == "fonti":
            shutil.copytree(src, os.path.join(d, name))
    return d


def passes(d):
    p = subprocess.run([sys.executable, "-B", TEST], cwd=d, capture_output=True, timeout=900)
    return p.returncode == 0, p.stdout.decode(errors="replace").strip().splitlines()[-1:]


def main():
    d = copy_dir()
    ok, tail = passes(d)
    shutil.rmtree(d)
    print("unmutated:", "PASS" if ok else "FAIL", tail)
    if not ok:
        return 1
    alive = 0
    for name, old, new in MUTANTS:
        d = copy_dir()
        path = os.path.join(d, AC)
        src = open(path).read()
        if src.count(old) != 1:
            print("MUTANT TEXT NOT FOUND EXACTLY ONCE:", name)
            return 1
        open(path, "w").write(src.replace(old, new))
        ok, tail = passes(d)
        shutil.rmtree(d)
        alive += ok
        print("%-50s %s %s" % (name, "ALIVE" if ok else "killed", tail))
    print("mutants: %d, killed %d, alive %d" % (len(MUTANTS), len(MUTANTS) - alive, alive))
    return 1 if alive else 0


if __name__ == "__main__":
    sys.exit(main())
