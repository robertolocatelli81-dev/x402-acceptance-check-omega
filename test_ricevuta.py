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
    after 1 s (the large receipt arrives whole: the checker waits for the reader, as a blocking write would) and to
    one never read (the checker is still waiting after 1.5 s, like `cat` would be), and to a slow pipe (whole),
  - in process, with sys.stdout a StringIO (no bytes below it: the receipt goes through the text layer),
  - on a directory: the input_error reason is "not a regular file", the same bytes whatever descriptor was free,
  - with PYTHONIOENCODING set to nine encodings, buffered and -u, to a pipe, a new file and an appended file: the
    bytes equal those Python's own text layer writes there (a byte order mark only where that layer writes one),
  - in process, main() with sys.stdout a TextIOWrapper over a pipe whose encoding is spelled UTF-16, utf_32, U16 or
    UTF-8-SIG: the same bytes as that wrapper writes for the same text,
  - from a copy without a bytecode cache, once under `ulimit -f 1` and once without: the second run gives the
    verdict and no __pycache__ is written,
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
    rc, body, _ = run_bash(paths["input_error"], '>"$OUT"', d)
    rep = json.loads(body.decode()) if body else {}
    check("input_error receipt", rep.get("result") == "input_error" and
          rep.get("reasons", [""]) == ["cannot read case: not a regular file"], repr(body))
    expected["input_error"] = (3, body)
    # the reason must not name the descriptor the case was opened on (2 when stderr is closed, 3 otherwise)
    rc, body2, _ = run_bash(paths["input_error"], '>"$OUT" 2>&-', d)
    check("input_error receipt the same with stderr closed", rc == 3 and body2 == body, repr(body2))
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
        check("%s non-blocking pipe read after 1 s: receipt whole, the verdict's code" % envname,
              p.returncode == 0 and got == expected["verified_big"][1] and err == b"",
              "rc=%r, %d of %d bytes, stderr %r" % (p.returncode, len(got), len(expected["verified_big"][1]), err[-120:]))
        r, w = os.pipe()                                     # non-blocking pipe kept open and never read
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        p = subprocess.Popen([sys.executable, "-B", AC, paths["verified_big"]], stdout=w, stderr=subprocess.PIPE,
                             env=env)
        os.close(w)
        time.sleep(1.5)
        waiting = p.poll() is None                           # the checker waits for the reader (as a blocking write)
        p.kill()
        err = p.communicate()[1]
        got = b""
        while True:
            try:
                b = os.read(r, 1 << 16)
            except BlockingIOError:
                break
            if not b:
                break
            got += b
        os.close(r)
        check("%s non-blocking pipe never read: the checker is still waiting after 1.5 s" % envname,
              waiting and err == b"" and expected["verified_big"][1].startswith(got) and 0 < len(got) < len(expected["verified_big"][1]),
              "exited rc=%r, %d bytes in the pipe, stderr %r" % (p.returncode, len(got), err[-120:]))
        # a non-blocking pipe already full before the checker starts, a small receipt: with a buffered stdout the
        # whole receipt fits the buffer and the full pipe is met at the flush; read after 1.5 s it arrives whole.
        # While it waits the checker must sleep in select, not spin (CPU time from /proc, Linux).
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
        pre = 0
        while True:
            try:
                pre += os.write(w, b"P" * 4096)
            except BlockingIOError:
                break
        for k in ("verified", "verified_big"):
            if k == "verified_big":                          # the large receipt: the pipe starts empty
                r, w = os.pipe()
                fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
                pre = 0
            p = subprocess.Popen([sys.executable, "-B", AC, paths[k]], stdout=w, stderr=subprocess.PIPE, env=env)
            os.close(w)
            time.sleep(1.5)
            cpu = None
            if os.path.exists("/proc/%d/stat" % p.pid):
                st = open("/proc/%d/stat" % p.pid).read().rsplit(")", 1)[1].split()
                cpu = (int(st[11]) + int(st[12])) / float(os.sysconf("SC_CLK_TCK"))
            waiting = p.poll() is None
            check("%s %s: waiting on a full non-blocking pipe after 1.5 s" % (envname, k), waiting, "rc=%r" % p.returncode)
            check("%s %s: the wait sleeps (CPU < 0.6 s of 1.5 s)" % (envname, k), cpu is not None and cpu < 0.6,
                  "cpu=%r s" % cpu)
            got = b""
            while True:
                b = os.read(r, 1 << 16)
                if not b:
                    break
                got += b
            os.close(r)
            err = p.stderr.read()
            p.wait(timeout=120)
            check("%s %s: pre-filled pipe read late: receipt whole, the verdict's code" % (envname, k),
                  p.returncode == expected[k][0] and got[pre:] == expected[k][1] and err == b"",
                  "rc=%r, %d of %d bytes, stderr %r" % (p.returncode, len(got) - pre, len(expected[k][1]), err[-120:]))
        p = subprocess.Popen([sys.executable, "-B", AC, paths["verified_big"]], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
        time.sleep(0.5)
        o, e = p.communicate(timeout=120)
        check("%s slow pipe whole" % envname, p.returncode == 0 and o == expected["verified_big"][1],
              "rc=%r, %d bytes" % (p.returncode, len(o)))

    # main() in process with sys.stdout a text stream without .buffer (a StringIO): the receipt goes through it
    code = ("import io, sys, json, acceptance_check as ac; s = io.StringIO(); sys.stdout = s; rc = ac.main(['x', sys.argv[1]]); "
            "sys.stdout = sys.__stdout__; sys.stdout.write(json.dumps([rc, s.getvalue()]))")
    for k in ("verified", "malformed", "verified_big"):
        p = subprocess.run([sys.executable, "-B", "-c", code, paths[k]], cwd=HERE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=120)
        try:
            rc, text = json.loads(p.stdout.decode())
        except ValueError:
            rc, text = None, None
        check(k + " sys.stdout StringIO: verdict and the whole receipt", rc == expected[k][0] and
              text is not None and text.encode() == expected[k][1] and p.stderr == b"", repr((p.returncode, p.stderr[-200:])))

    # main() in process with sys.stdout a TextIOWrapper over an io.BytesIO (pytest's capsys): a byte stream with no
    # descriptor; the receipt goes to it whole (no fileno() is needed unless a non-blocking stdout must be waited for)
    code = ("import io, sys, json, acceptance_check as ac; s = io.TextIOWrapper(io.BytesIO(), encoding='UTF-8', newline='', "
            "write_through=True); sys.stdout = s; rc = ac.main(['x', sys.argv[1]]); sys.stdout = sys.__stdout__; "
            "sys.stdout.write(json.dumps([rc, s.buffer.getvalue().decode()]))")
    for k in ("verified", "malformed", "verified_big"):
        p = subprocess.run([sys.executable, "-B", "-c", code, paths[k]], cwd=HERE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=120)
        try:
            rc, text = json.loads(p.stdout.decode())
        except ValueError:
            rc, text = None, None
        check(k + " sys.stdout TextIOWrapper(BytesIO): verdict and the whole receipt", rc == expected[k][0] and
              text is not None and text.encode() == expected[k][1] and p.stderr == b"", repr((p.returncode, p.stderr[-200:])))

    for args in ([], ["a", "b"]):
        p = subprocess.run(["bash", "-c", '"$@" 2>&-', "x", sys.executable, "-B", AC] + args,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        check("usage %r stderr closed rc" % args, p.returncode == 3, "rc=%r" % p.returncode)
        p = subprocess.run([sys.executable, "-B", AC] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        check("usage %r rc" % args, p.returncode == 3 and p.stdout == b"" and
              p.stderr == b"usage: acceptance_check.py CASE.json\n", repr((p.returncode, p.stdout, p.stderr)))

    # byte order mark (13/10/2026): the receipt's bytes against Python's own text layer writing the same text to the
    # same kind of stdout, with the same environment; at acfad3d utf-16 / utf-32 on a pipe carried a BOM (ff fe 7b 00)
    # that the text layer does not write there
    text_v = expected["verified"][1].decode("ascii")
    ref_prog = "import sys; sys.stdout.write(open(sys.argv[1], encoding='ascii').read())"
    txt = os.path.join(d, "receipt.txt")
    with open(txt, "w", encoding="ascii") as f:
        f.write(text_v)
    for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-32", "UTF-16", "utf_32", "utf-16-le", "cp1252", "latin-1"):
        for unbuf in (False, True):
            env = dict(os.environ, PYTHONIOENCODING=enc)
            env.pop("PYTHONUNBUFFERED", None)
            if unbuf:
                env["PYTHONUNBUFFERED"] = "1"
            tag = "BOM %s %s" % (enc, "-u" if unbuf else "buffered")
            p = subprocess.run([sys.executable, "-B", AC, paths["verified"]], env=env, capture_output=True, timeout=60)
            r = subprocess.run([sys.executable, "-B", "-c", ref_prog, txt], env=env, capture_output=True, timeout=60)
            check(tag + " pipe", p.returncode == 0 and r.returncode == 0 and p.stdout == r.stdout,
                  "%r vs %r" % (p.stdout[:4], r.stdout[:4]))
            for mode, pre in (("new file", None), ("appended", b"pre\n")):
                got, ref = os.path.join(d, "bom_got"), os.path.join(d, "bom_ref")
                for fn in (got, ref):
                    with open(fn, "wb") as f:
                        f.write(pre or b"")
                fm = "ab" if pre else "wb"
                with open(got, fm) as f:
                    rc = subprocess.run([sys.executable, "-B", AC, paths["verified"]], env=env, stdout=f,
                                        stderr=subprocess.DEVNULL, timeout=60).returncode
                with open(ref, fm) as f:
                    subprocess.run([sys.executable, "-B", "-c", ref_prog, txt], env=env, stdout=f, timeout=60)
                check(tag + " " + mode, rc == 0 and open(got, "rb").read() == open(ref, "rb").read(),
                      "%r vs %r" % (open(got, "rb").read()[:8], open(ref, "rb").read()[:8]))

    # in process, an encoding name as the caller spelled it (a command gets the codec's own name): a TextIOWrapper with
    # encoding "UTF-16" or "utf_32" over a pipe, main() called; the bytes must equal the text layer's for the same text
    code = ("import io, os, sys, acceptance_check as ac\n"
            "def run(enc, through_main):\n"
            "    r, w = os.pipe()\n"
            "    s = io.TextIOWrapper(io.FileIO(w, 'w'), encoding=enc)\n"
            "    old, sys.stdout = sys.stdout, s\n"
            "    try:\n"
            "        if through_main:\n"
            "            rc = ac.main(['x', sys.argv[1]])\n"
            "        else:\n"
            "            rc = 0; s.write(open(sys.argv[2], encoding='ascii').read())\n"
            "        s.flush()\n"
            "    finally:\n"
            "        sys.stdout = old; s.close()\n"
            "    data = b''\n"
            "    while True:\n"
            "        b = os.read(r, 65536)\n"
            "        if not b: break\n"
            "        data += b\n"
            "    os.close(r)\n"
            "    return rc, data\n"
            "for enc in ('UTF-16', 'utf_32', 'U16', 'UTF-8-SIG'):\n"
            "    a, b = run(enc, True), run(enc, False)\n"
            "    print(enc, 'same' if a == b else 'differ %r %r' % (a[1][:4], b[1][:4]))\n")
    p = subprocess.run([sys.executable, "-B", "-c", code, paths["verified"], txt], cwd=HERE, capture_output=True,
                       timeout=60)
    lines = p.stdout.decode("ascii", "replace").splitlines()
    check("BOM in process, encoding names as spelled", p.returncode == 0 and len(lines) == 4 and
          all(l.endswith(" same") for l in lines), repr((p.returncode, lines, p.stderr[-200:])))

    # bytecode cache (13/10/2026): run as a command the checker writes no __pycache__; at acfad3d CPython 3.9 and 3.11
    # installed a .pyc of ed25519_rfc8032 cut by `ulimit -f 1`, and every later run exited 1 (EOFError)
    pyc = tempfile.mkdtemp()
    for name in ("acceptance_check.py", "ed25519_rfc8032.py"):
        with open(os.path.join(HERE, name), "rb") as f_in, open(os.path.join(pyc, name), "wb") as f_out:
            f_out.write(f_in.read())
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}
    cmd = [sys.executable, os.path.join(pyc, "acceptance_check.py"), paths["verified"]]
    lim = subprocess.run(["bash", "-c", 'ulimit -f 1; "$@" >/dev/null 2>&1; echo $?', "x"] + cmd, env=env,
                         capture_output=True, timeout=60)
    check("bytecode: run under ulimit -f 1", lim.stdout.strip() == b"0", repr(lim.stdout))
    p = subprocess.run(cmd, env=env, capture_output=True, timeout=60)
    check("bytecode: later run", p.returncode == 0 and p.stdout == expected["verified"][1] and p.stderr == b"",
          "rc=%r %r" % (p.returncode, p.stderr[-120:]))
    check("bytecode: no __pycache__ written", not os.path.exists(os.path.join(pyc, "__pycache__")),
          repr(os.listdir(pyc)))

    for f in FAILS:
        print("FAIL", f)
    print("test_ricevuta: %s (%d failures)" % ("OK" if not FAILS else "FAILED", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
