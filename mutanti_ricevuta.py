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
    ("no flush of the receipt", "                buf.flush()\n                return\n", "                return\n"),
    ("one write, short count ignored", "            try:\n                n = buf.write(data)\n                waited = False\n",
     "            try:\n                buf.write(data)\n                n = len(data)\n                waited = False\n"),
    ("raw write returning None (EAGAIN) not waited for",
     "            if n is None:                                    # raw stdout on a full non-blocking pipe: nothing taken\n                n, waited = 0, True\n",
     "            if n is None:\n                raise OSError(\"EAGAIN\")\n"),
    ("BlockingIOError of a buffered stdout not waited for",
     "                n = e.characters_written\n                waited = True\n", "                raise OSError(str(e))\n"),
    ("receipt written through the text layer (as at c3e44ef)",
     "        data = memoryview(_text_layer_bytes", "        out.write(text); out.flush(); return\n        data = memoryview(_text_layer_bytes"),
    ("descriptor asked for before writing (no receipt on a TextIOWrapper over BytesIO)",
     "        data = memoryview(", "        buf.fileno()\n        data = memoryview("),
    ("no text-layer fallback when stdout has no .buffer (StringIO)",
     "        if buf is None:                                      # an in-process text stream (StringIO): no bytes below it\n"
     "            out.write(text)\n            out.flush()\n            return\n", ""),
    ("write error not caught", "    except OSError as e:\n        _quiet(sys.stdout)\n",
     "    except ZeroDivisionError as e:\n        _quiet(sys.stdout)\n"),
    ("exit with the verdict when the receipt is lost", "        return EXIT_RECEIPT_NOT_WRITTEN\n",
     "        return rep[\"exit\"]\n"),
    ("exit 1 when the receipt is lost", "EXIT_RECEIPT_NOT_WRITTEN = 74", "EXIT_RECEIPT_NOT_WRITTEN = 1"),
    ("exit 0 when the receipt is lost", "EXIT_RECEIPT_NOT_WRITTEN = 74", "EXIT_RECEIPT_NOT_WRITTEN = 0"),
    ("stdout None not checked", "    if out is None:\n        raise OSError(\"stdout is closed\")\n", ""),
    ("stdout left as it is after the failure", "        _quiet(sys.stdout)\n        _say(", "        _say("),
    ("no dup2 in _quiet (the try body stays: pass)", "            os.dup2(null, fd)\n", "            pass\n"),
    ("no stderr line", "        _say(\"receipt not written: %s\\n\" % e)\n", ""),
    ("stderr None not checked", "        if err is None:\n            return\n", ""),
    ("stderr error not caught", "    except (OSError, ValueError):\n        _quiet(err)\n",
     "    except ZeroDivisionError:\n        _quiet(err)\n"),
    ("stderr left as it is after a stderr failure", "    except (OSError, ValueError):\n        _quiet(err)\n",
     "    except (OSError, ValueError):\n        pass\n"),
    ("usage written without the guard", "        _say(\"usage: acceptance_check.py CASE.json\\n\")\n",
     "        sys.stderr.write(\"usage: acceptance_check.py CASE.json\\n\")\n"),
    ("ValueError of a closed stdout not converted", "    except ValueError as e:                                  # I/O",
     "    except ZeroDivisionError as e:                           # I/O"),
    ("regular-file check after fdopen: the reason names a descriptor number",
     "        try:\n            if not stat.S_ISREG(os.fstat(fd).st_mode):        # checked on the descriptor, before any read: the\n"
     "                raise ValueError(\"not a regular file\")        # reason never names a descriptor number\n"
     "        except BaseException:\n            os.close(fd)\n            raise\n        with os.fdopen(fd, \"rb\") as f:\n",
     "        with os.fdopen(fd, \"rb\") as f:\n            if not stat.S_ISREG(os.fstat(fd).st_mode):\n"
     "                raise ValueError(\"not a regular file\")\n"),
    ("flush on a full non-blocking pipe not waited for",
     "            except BlockingIOError:\n                _wait_writable(buf)\n",
     "            except ZeroDivisionError:\n                _wait_writable(buf)\n"),
    ("flush loop spins instead of waiting", "            except BlockingIOError:\n                _wait_writable(buf)\n",
     "            except BlockingIOError:\n                pass\n"),
    ("write loop spins instead of waiting", "            if data and waited:\n                _wait_writable(buf)\n",
     "            if data and waited:\n                pass\n"),
    ("select with a zero timeout (spins)", "select.select([], [buf.fileno()], [])", "select.select([], [buf.fileno()], [], 0)"),
    # 13/10/2026: byte order mark and bytecode cache
    ("receipt encoded with str.encode (as at acfad3d: a BOM on a pipe and after an append)",
     "        data = memoryview(_text_layer_bytes(out, buf, text))\n",
     "        data = memoryview(text.encode(out.encoding or \"utf-8\", out.errors or \"strict\"))\n"),
    ("BOM never suppressed", "        enc.setstate(0)                                      # no byte order mark\n",
     "        pass\n"),
    ("BOM kept past offset 0 of a seekable stdout", "    if (seekable and not at_start) or (not seekable",
     "    if (not seekable"),
    ("BOM kept on a utf-16 pipe", 'name in ("utf-16", "utf-32")', 'name in ("utf-32",)'),
    ("BOM kept on a utf-32 pipe", 'name in ("utf-16", "utf-32")', 'name in ("utf-16",)'),
    ("encoding name not normalised (aliases UTF-16, utf_32)", "codecs.lookup(encoding).name in", "encoding in"),
    ("offset not read: every seekable stdout counts as at its start", "        at_start = seekable and buf.tell() == 0\n",
     "        at_start = seekable\n"),
    ("BOM suppressed on every pipe (utf-8-sig too)", "(not seekable and codecs.lookup(encoding).name in (\"utf-16\", \"utf-32\"))",
     "(not seekable)"),
    ("bytecode cache written when run as a command", "    sys.dont_write_bytecode = True", "    pass"),
    ("bytecode guard on the wrong branch", 'if __name__ == "__main__":   # run as a command', 'if __name__ != "__main__":   # run as a command'),
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
