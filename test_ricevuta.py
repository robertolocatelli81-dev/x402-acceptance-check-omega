# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""The receipt is either written whole to stdout, or the exit code is 74 (2026-10-12).

Real processes only (no mock of the write): acceptance_check.py is run on a verified case, a malformed case,
an input_error case and a verified case whose receipt is larger than 64 KiB, with stdout
  - to a file (control: exit code of the verdict, receipt byte-identical to check() in process),
  - to a slow pipe (the reader starts reading after 0.5 s: the receipt still arrives whole),
  - to /dev/full (ENOSPC), to a pipe whose reader is already closed (EPIPE), closed (>&-),
  - and the same three with stderr closed or full as well; main() is also called with sys.stdout closed,
  - to `| head -c 0`, the checker started 0.2 s after head (50 runs per case),
  - with PYTHONUNBUFFERED=1 and without: under `ulimit -f 4`, to `| head -c 100`, to a non-blocking pipe read
    after 1 s and to one never read (the large receipt), and to a slow pipe (whole),
and, in each mode where the receipt is lost, the exit code must be 74 with one line "receipt not written: ..."
on stderr when stderr works, and no traceback. The usage error keeps exit 3 with stderr closed.

python3 test_ricevuta.py   -> exit 0 iff every check passes
"""
import copy
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time

import acceptance_check as ac

HERE = os.path.dirname(os.path.abspath(__file__))
AC = os.path.join(HERE, "acceptance_check.py")
VECTORS = os.path.join(HERE, "fonti", "d750291_vectors.json")
FAILS = []


def check(name, cond, detail=""):
    if not cond:
        FAILS.append("%s %s" % (name, detail))


def run_bash(path, redir, d):
    """Run the checker under bash with a redirection; return (rc, stdout bytes or None, stderr bytes)."""
    out = os.path.join(d, "out")
    if os.path.exists(out):
        os.remove(out)
    script = '"$0" -B "$1" "$2" ' + redir
    p = subprocess.run(["bash", "-c", script, sys.executable, AC, path], env=dict(os.environ, OUT=out),
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
    body = open(out, "rb").read() if os.path.exists(out) else None
    return p.returncode, body, p.stderr


def run_closed_pipe(path, stderr_closed=False):
    r, w = os.pipe()
    os.close(r)                                              # the reader is gone before the checker starts
    try:
        p = subprocess.run([sys.executable, "-B", AC, path], stdout=w,
                           stderr=subprocess.PIPE, timeout=120,
                           **({"preexec_fn": lambda: os.close(2)} if stderr_closed else {}))
    finally:
        os.close(w)
    return p.returncode, p.stderr


def run_slow_pipe(path):
    p = subprocess.Popen([sys.executable, "-B", AC, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)
    out, err = p.communicate(timeout=120)
    return p.returncode, out, err


def lost(name, rc, err, stderr_works=True):
    check(name + " rc", rc == 74, "rc=%r" % rc)
    check(name + " no traceback", b"Traceback" not in err and b"Exception ignored" not in err, repr(err[-200:]))
    if stderr_works:
        lines = err.decode("utf-8", "replace").splitlines()
        check(name + " one stderr line", len(lines) == 1 and lines[0].startswith("receipt not written: "),
              repr(err[-200:]))


def main():
    vec = {v["id"]: v["case"] for v in json.load(open(VECTORS))["vectors"]}
    d = tempfile.mkdtemp()
    big = copy.deepcopy(vec["acc-accepted-verified"])
    for i in range(3000):
        big["acceptance"]["m%05d" % i] = 1                   # README sentence 1: ignored, listed in notes
    cases = {"verified": vec["acc-accepted-verified"], "malformed": vec["acc-confirming-party-absent"],
             "verified_big": big}
    paths = {}
    expected = {}
    for k, c in cases.items():
        paths[k] = os.path.join(d, k + ".json")
        with open(paths[k], "w") as f:
            json.dump(c, f)
        rep = ac.check(copy.deepcopy(c))
        expected[k] = (rep["exit"], (json.dumps(rep, indent=1, sort_keys=True) + "\n").encode())
    paths["input_error"] = os.path.join(d, "a_directory")
    os.mkdir(paths["input_error"])
    rc, body, _ = run_bash(paths["input_error"], '>"$OUT"', d)   # its reason names an fd number: taken from a run
    rep = json.loads(body.decode()) if body else {}
    check("input_error receipt", rep.get("result") == "input_error" and
          rep.get("reasons", [""])[0].startswith("cannot read case: [Errno 21]"), repr(body))
    expected["input_error"] = (3, body)
    check("big receipt > 64 KiB", len(expected["verified_big"][1]) > 65536, str(len(expected["verified_big"][1])))
    check("verdicts", [expected[k][0] for k in ("verified", "malformed", "input_error", "verified_big")] == [0, 1, 3, 0],
          str({k: v[0] for k, v in expected.items()}))

    for k, path in paths.items():
        rc_v, body_v = expected[k]
        rc, body, err = run_bash(path, '>"$OUT"', d)
        check(k + " file rc", rc == rc_v, "rc=%r" % rc)
        check(k + " file receipt identical", body == body_v)
        check(k + " file stderr empty", err == b"", repr(err[:200]))

        rc, out, err = run_slow_pipe(path)
        check(k + " slow pipe rc", rc == rc_v, "rc=%r" % rc)
        check(k + " slow pipe receipt whole", out == body_v, "%d of %d bytes" % (len(out), len(body_v)))

        rc, _, err = run_bash(path, ">/dev/full", d)
        lost(k + " /dev/full", rc, err)
        rc, err = run_closed_pipe(path)
        lost(k + " closed pipe", rc, err)
        rc, _, err = run_bash(path, ">&-", d)
        lost(k + " stdout closed", rc, err)
        check(k + " stdout closed reason", b"stdout is closed" in err, repr(err[-200:]))

        for redir, label in ((">/dev/full 2>&-", "/dev/full, stderr closed"),
                             (">&- 2>&-", "stdout and stderr closed"),
                             (">/dev/full 2>/dev/full", "/dev/full, stderr full")):
            rc, _, err = run_bash(path, redir, d)
            lost(k + " " + label, rc, err, stderr_works=False)
        rc, err = run_closed_pipe(path, stderr_closed=True)
        lost(k + " closed pipe, stderr closed", rc, err, stderr_works=False)

    # `| head -c 0`: head starts first and the checker 0.2 s later, so head has exited before the write; 50 runs
    for k in ("verified", "malformed"):
        rcs = []
        for _ in range(50):
            p = subprocess.run(["bash", "-c", '{ sleep 0.2; exec "$0" -B "$1" "$2"; } | head -c 0; '
                                'echo "${PIPESTATUS[0]}" >&2', sys.executable, AC, paths[k]],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
            lines = p.stderr.decode("utf-8", "replace").splitlines()
            rcs.append(lines[-1] if lines else "")
            lost(k + " | head -c 0", int(lines[-1]) if lines and lines[-1].isdigit() else -1,
                 "\n".join(lines[:-1]).encode() + (b"\n" if len(lines) > 1 else b""))
        check(k + " | head -c 0 50/50", rcs == ["74"] * 50, str(sorted(set(rcs))))

    # main() called by a program that has closed sys.stdout (a closed file object, not None)
    code = "import sys, acceptance_check as ac; sys.stdout.close(); sys.exit(ac.main(['x', sys.argv[1]]))"
    for k in ("verified", "malformed"):
        p = subprocess.run([sys.executable, "-B", "-c", code, paths[k]], cwd=HERE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=120)
        lost(k + " sys.stdout closed object", p.returncode, p.stderr)

    # -u / PYTHONUNBUFFERED: sys.stdout.buffer is then a raw FileIO, whose write() can be short without raising.
    # A file size limit (ulimit -f 4: 4096 bytes), a reader that reads 100 bytes and exits, a non-blocking pipe
    # read only after 1 s: the big receipt is lost (74); the small one under the limit is whole (control).
    out = os.path.join(d, "out")
    for envname, extra in (("buffered", {}), ("PYTHONUNBUFFERED", {"PYTHONUNBUFFERED": "1"})):
        env = dict(os.environ, OUT=out, **extra)
        for k in ("verified", "verified_big"):
            if os.path.exists(out):
                os.remove(out)
            p = subprocess.run(["bash", "-c", 'ulimit -f 4; "$0" -B "$1" "$2" >"$OUT"', sys.executable, AC, paths[k]],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
            body = open(out, "rb").read() if os.path.exists(out) else None
            if k == "verified":
                check("%s ulimit -f 4 %s rc" % (envname, k), p.returncode == 0 and body == expected[k][1],
                      "rc=%r" % p.returncode)
            else:
                lost("%s ulimit -f 4 %s" % (envname, k), p.returncode, p.stderr)
        p = subprocess.run(["bash", "-c", '{ sleep 0.2; exec "$0" -B "$1" "$2"; } | head -c 100 >/dev/null; '
                            'echo "${PIPESTATUS[0]}" >&2', sys.executable, AC, paths["verified_big"]],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
        lines = p.stderr.decode("utf-8", "replace").splitlines()
        lost("%s | head -c 100 verified_big" % envname, int(lines[-1]) if lines and lines[-1].isdigit() else -1,
             "\n".join(lines[:-1]).encode() + (b"\n" if len(lines) > 1 else b""))
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        p = subprocess.Popen([sys.executable, "-B", AC, paths["verified_big"]], stdout=w, stderr=subprocess.PIPE,
                             env=env)
        os.close(w)
        time.sleep(1.0)
        got = b""
        while True:
            b = os.read(r, 1 << 16)
            if not b:
                break
            got += b
        os.close(r)
        err = p.stderr.read()
        p.wait(timeout=120)
        check("%s non-blocking pipe: receipt whole or 74" % envname,
              (p.returncode == 74) or (p.returncode == 0 and got == expected["verified_big"][1]),
              "rc=%r, %d bytes" % (p.returncode, len(got)))
        if p.returncode == 74:
            lost("%s non-blocking pipe" % envname, p.returncode, err)
        r, w = os.pipe()                                     # non-blocking pipe kept open and never read
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        p = subprocess.Popen([sys.executable, "-B", AC, paths["verified_big"]], stdout=w, stderr=subprocess.PIPE,
                             env=env)
        os.close(w)
        try:
            err = p.communicate(timeout=60)[1]
        except subprocess.TimeoutExpired:
            p.kill()
            err = p.communicate()[1]
        os.close(r)
        lost("%s non-blocking pipe never read" % envname, p.returncode, err)
        p = subprocess.Popen([sys.executable, "-B", AC, paths["verified_big"]], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
        time.sleep(0.5)
        o, e = p.communicate(timeout=120)
        check("%s slow pipe whole" % envname, p.returncode == 0 and o == expected["verified_big"][1],
              "rc=%r, %d bytes" % (p.returncode, len(o)))

    for args in ([], ["a", "b"]):
        p = subprocess.run(["bash", "-c", '"$@" 2>&-', "x", sys.executable, "-B", AC] + args,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        check("usage %r stderr closed rc" % args, p.returncode == 3, "rc=%r" % p.returncode)
        p = subprocess.run([sys.executable, "-B", AC] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        check("usage %r rc" % args, p.returncode == 3 and p.stdout == b"" and
              p.stderr == b"usage: acceptance_check.py CASE.json\n", repr((p.returncode, p.stdout, p.stderr)))

    for f in FAILS:
        print("FAIL", f)
    print("test_ricevuta: %s (%d failures)" % ("OK" if not FAILS else "FAILED", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
