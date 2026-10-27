"""Ghost Hunter's checks on a fake machine tree, and the narration guard with a scripted
model. No real /proc is read and no model is called."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from ghosthunt import checks as C
from ghosthunt import narrate as N

BOOT = int(time.time()) - 3 * 86400


def _w(root: Path, rel: str, data, mode: int = 0o644) -> Path:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        p.write_bytes(data)
    else:
        p.write_text(data)
    os.chmod(p, mode)
    return p


def _proc(root: Path, pid: int, name: str, exe: str | None, uid: int = 0, ppid: int = 1,
          cmd: str = "", tgid: int | None = None, start_ticks: int = 100) -> None:
    d = f"/proc/{pid}"
    _w(root, f"{d}/status", f"Name:\t{name}\nTgid:\t{tgid or pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    _w(root, f"{d}/cmdline", cmd.replace(" ", "\0").encode())
    _w(root, f"{d}/stat", f"{pid} ({name}) S {ppid} " + " ".join(["0"] * 17) + f" {start_ticks} 0\n")
    _w(root, f"{d}/cgroup", "0::/system.slice/x.service\n")
    if exe is not None:
        os.symlink(exe, root / d.lstrip("/") / "exe")


@pytest.fixture
def machine(tmp_path):
    _w(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    _w(tmp_path, "/proc/stat", f"cpu 0\nbtime {BOOT}\n")
    _w(tmp_path, "/proc/uptime", "300000.00 1.00\n")
    _w(tmp_path, "/proc/sys/kernel/pid_max", "200\n")
    _w(tmp_path, "/proc/sys/kernel/hostname", "web-01\n")
    _w(tmp_path, "/usr/sbin/sshd", "bin")
    _w(tmp_path, "/var/log/wtmp", b"x" * 384)
    return tmp_path


def _scan(root: Path, host_cls=C.Host):
    old = C.Host
    C.Host = host_cls
    try:
        return C.scan(root=str(root))
    finally:
        C.Host = old


def _kinds(s):
    return sorted(g.kind for g in s.ghosts)


def test_a_clean_machine_has_no_ghosts(machine):
    _proc(machine, 1, "systemd", "/usr/sbin/sshd", cmd="/sbin/init")
    s = _scan(machine)
    assert s.ghosts == [] and s.host == "web-01"


def test_deleted_memory_only_and_ownerless_processes(machine):
    _proc(machine, 10, "kworkerd", "/tmp/.x/kworkerd (deleted)", cmd="/tmp/.x/kworkerd")
    _proc(machine, 11, "x", "/memfd:payload (deleted)", cmd="x")
    _proc(machine, 12, "sshd", "/usr/sbin/sshd (deleted)", cmd="sshd")     # an update: the file is back
    _proc(machine, 13, "sleep", "/usr/sbin/sshd", uid=4242, cmd="sleep 999")
    s = _scan(machine)
    assert _kinds(s) == ["bodiless", "nameless", "restless", "undead"]
    undead = next(g for g in s.ghosts if g.kind == "undead")
    assert undead.evidence["program"] == "/tmp/.x/kworkerd" and undead.evidence["pid"] == 10
    assert next(g for g in s.ghosts if g.kind == "nameless").evidence["user"] == "uid 4242 (no such account)"


def test_container_processes_are_left_to_their_container(machine):
    _w(machine, "/etc/subuid", "alice:100000:65536\n")
    _proc(machine, 20, "bash", "/usr/sbin/sshd", uid=100000, cmd="bash")
    _w(machine, "/proc/21/cgroup", "")
    _proc(machine, 22, "nginx", "/usr/sbin/sshd", uid=5555, cmd="nginx")
    _w(machine, "/proc/22/cgroup", "0::/lxc.payload.web/system.slice/nginx.service\n")
    s = _scan(machine)
    assert s.ghosts == [] and any("inside containers" in b for b in s.blind_spots)


class _Hiding(C.Host):
    """A rootkit's view: process 50 is left out of the /proc listing."""
    def listdir(self, p):
        out = super().listdir(p)
        return [x for x in out if x != "50"] if out is not None and p == "/proc" else out


def test_a_process_left_out_of_the_listing_is_hidden_but_a_thread_is_not(machine):
    _proc(machine, 1, "systemd", "/usr/sbin/sshd", cmd="/sbin/init")
    _proc(machine, 50, "rootkitd", "/usr/sbin/sshd", cmd="rootkitd")
    _proc(machine, 51, "worker", "/usr/sbin/sshd", tgid=1, cmd="/sbin/init")   # a thread of 1
    s = _scan(machine, _Hiding)
    hidden = [g for g in s.ghosts if g.kind == "hidden"]
    assert [g.evidence["pid"] for g in hidden] == [50] and hidden[0].severity == "critical"


def test_a_process_born_after_the_listing_is_not_hidden(machine):
    now_ticks = int((time.time() + 5 - BOOT) * os.sysconf("SC_CLK_TCK"))
    _proc(machine, 50, "sleep", "/usr/sbin/sshd", cmd="sleep 5", start_ticks=now_ticks)
    assert [g for g in _scan(machine, _Hiding).ghosts if g.kind == "hidden"] == []


def test_what_departed_accounts_left_behind(machine):
    home = machine / "home" / "olddev"
    _w(machine, "/home/olddev/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nz test\n")
    _w(machine, "/home/emptyhome/.profile", "")
    if os.geteuid() != 0:
        pytest.skip("making a folder owned by a missing account needs root")
    os.chown(home, 4243, 4243)
    os.chown(machine / "home" / "emptyhome", 4244, 4244)
    _w(machine, "/var/spool/cron/crontabs/olddev", "* * * * * /tmp/x\n")
    s = _scan(machine)
    homes = {g.evidence["home"]: g for g in s.ghosts if g.kind == "home"}
    assert homes[str(machine / "home" / "olddev").replace(str(machine), "")].severity == "high"


def test_departed_account_cron_and_preload_and_empty_history(machine):
    _w(machine, "/var/spool/cron/crontabs/olddev", "* * * * * /tmp/x\n")
    _w(machine, "/var/spool/cron/crontabs/alice", "\n")
    _w(machine, "/etc/ld.so.preload", "/usr/lib/libhide.so\n")
    _w(machine, "/var/log/wtmp", b"")
    _w(machine, "/var/log/auth.log", AUTH_WITH_LOGIN)
    s = _scan(machine)
    assert _kinds(s) == ["cron", "memories", "possessed"]
    assert next(g for g in s.ghosts if g.kind == "cron").evidence["account"] == "olddev"
    assert next(g for g in s.ghosts if g.kind == "possessed").evidence["libraries"] == ["/usr/lib/libhide.so"]


def test_a_compiled_program_in_tmp_owned_by_no_account(machine):
    _w(machine, "/tmp/.cache/miner", b"\x7fELF" + b"\0" * 60, mode=0o755)
    _w(machine, "/tmp/notes.sh", "#!/bin/sh\n", mode=0o755)        # a script, not a compiled program
    _w(machine, "/tmp/pip-build/_cffi.cpython-312.so", b"\x7fELF" + b"\0" * 60, mode=0o755)   # a library
    s = _scan(machine)
    assert [g.evidence["file"] for g in s.ghosts if g.kind == "grave"] == ["/tmp/.cache/miner"]


def test_machine_text_is_cleaned():
    assert C.clean("evil\x1b[2Jname‮") == "evil?[2Jname?"
    assert len(C.clean("x" * 500)) == 200


# ---------------------------------------------------------------------------- the voice
GHOST = C.Ghost("UNDEAD-1", "undead", "A program still running after its file was deleted", "high",
                {"pid": 4242, "program": "/tmp/.x/kworkerd", "user": "root", "started": "2026-10-27 09:12 UTC"},
                "Its file is gone but it keeps running.", "Copy its program from /proc/4242/exe first.")


class _Scripted(N.Model):
    def __init__(self, replies):
        super().__init__(base_url="http://model.invalid", model="test")
        self.replies = list(replies)
        self.prompts = []

    def chat(self, system, messages, max_tokens=220):
        self.prompts.append((system, messages))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_a_narration_that_sticks_to_the_evidence_is_used():
    text, from_model = N.narrate(GHOST, _Scripted(["A soul without a body lingers as 4242 in /tmp/.x/kworkerd. "
                                                   "Copy /proc/4242/exe before it fades."]))
    assert from_model and "4242" in text


@pytest.mark.parametrize("invented", [
    "It phones home to 203.0.113.5.",              # an address the evidence doesn't have
    "It was dropped by /var/www/shell.php.",        # a path
    "It has run since 2019.",                       # a number
])
def test_an_invented_fact_falls_back_to_plain_words(invented):
    text, from_model = N.narrate(GHOST, _Scripted([f"A ghost stirs at 4242. {invented}"]))
    assert not from_model and text.startswith("Its file is gone")


def test_no_model_means_plain_words_not_a_failure():
    text, from_model = N.narrate(GHOST, _Scripted([N.ModelError("down")]))
    assert not from_model and "Copy its program" in text


def test_the_ghost_answers_only_from_its_evidence():
    m = _Scripted(["I was born from /tmp/.x/kworkerd and I answer to 4242.", "My master lives at 198.51.100.7."])
    ok, trusted = N.ask_ghost(GHOST, "what are you?", [], m)
    assert trusted and "/tmp/.x/kworkerd" in ok
    withheld, trusted = N.ask_ghost(GHOST, "who sent you?", [], m)
    assert not trusted and "withheld" in withheld and "198.51.100.7" in withheld
    # machine text reaches the model as data inside the evidence block, never as the question
    assert "EVIDENCE" in m.prompts[0][1][0]["content"] and m.prompts[0][1][-1]["content"] == "what are you?"


def test_a_think_block_is_dropped_from_the_reply(monkeypatch):
    """Reasoning models wrap their thinking in <think>; only the answer is shown."""
    import json as _json
    import io
    import urllib.request

    body = _json.dumps({"choices": [{"message": {"content": "<think>secret plan</think> A cold wind at 4242."}}]})

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: _Resp(body.encode()))
    assert N.Model(base_url="http://x.invalid").chat("s", []) == "A cold wind at 4242."


# ---------------------------------------------------------------------------- edge cases
def test_directory_accounts_count_as_accounts(monkeypatch):
    """LDAP/SSSD users aren't in /etc/passwd: on the machine itself they are looked up
    the way the system does, so they aren't taken for departed accounts."""
    import pwd

    class _Pw:
        pw_name = "ldapuser"
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: _Pw() if uid == 70001 else (_ for _ in ()).throw(KeyError(uid)))
    monkeypatch.setattr(pwd, "getpwnam", lambda n: _Pw() if n == "ldapuser" else (_ for _ in ()).throw(KeyError(n)))
    acc = C.Accounts({0: "root"}, {"root": "/bin/bash"}, use_nss=True)
    assert 70001 in acc and acc.get(70001) == "ldapuser" and acc.has_name("ldapuser")
    assert 70002 not in acc and not acc.has_name("gone")
    assert 70001 not in C.Accounts({0: "root"}, {}, use_nss=False)       # a scan of another tree: files only


def test_orphan_cron_on_rhel_and_alpine_layouts(machine):
    _w(machine, "/var/spool/cron/olddev", "* * * * * /tmp/x\n")           # RHEL family
    _w(machine, "/etc/crontabs/ghost", "* * * * * /tmp/y\n")              # Alpine
    _w(machine, "/var/spool/cron/crontabs/alice", "\n")                   # Debian, a living account
    s = _scan(machine)
    assert sorted(g.evidence["account"] for g in s.ghosts if g.kind == "cron") == ["ghost", "olddev"]


AUTH_WITH_LOGIN = "Oct 27 09:00:01 web-01 sshd[811]: Accepted publickey for alice from 192.0.2.4 port 50000 ssh2\n"


def test_newer_systems_keep_logins_in_wtmpdb(machine):
    _w(machine, "/var/log/auth.log", AUTH_WITH_LOGIN)
    (machine / "var/log/wtmp").unlink()
    _w(machine, "/var/lib/wtmpdb/wtmp.db", b"SQLite format 3\0" + b"\0" * 100)
    assert [g for g in _scan(machine).ghosts if g.kind == "memories"] == []
    _w(machine, "/var/lib/wtmpdb/wtmp.db", b"")
    assert [g.evidence["file"] for g in _scan(machine).ghosts if g.kind == "memories"] == ["/var/lib/wtmpdb/wtmp.db"]


def test_a_container_runtime_in_memory_is_not_a_high_ghost(machine):
    _proc(machine, 30, "runc", "/memfd:runc_cloned:/proc/self/exe (deleted)", cmd="runc init")
    [g] = _scan(machine).ghosts
    assert g.kind == "bodiless" and g.severity == "low"


def test_a_planted_fifo_or_link_cannot_hang_or_trick_the_scan(machine, tmp_path):
    keys = machine / "home/olddev/.ssh/authorized_keys"
    keys.parent.mkdir(parents=True)
    os.mkfifo(keys)                                     # reading a FIFO would block forever
    host = C.Host(str(machine))
    start = time.time()
    assert host.read("/home/olddev/.ssh/authorized_keys") is None and time.time() - start < 1
    keys.unlink()
    secret = _w(machine, "/etc/secret-file", "ssh-rsa AAAA x\n" * 3)
    os.symlink(secret, keys)                            # a key file linked to somewhere else
    assert host.read("/home/olddev/.ssh/authorized_keys") is None
    assert host.read("/etc/secret-file") is not None    # system files are read normally


def test_hidepid_is_reported_as_a_blind_spot(machine):
    if os.geteuid() == 0:
        pytest.skip("root sees every process regardless")
    _w(machine, "/proc/mounts", "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0\n")
    assert any("hidepid" in b for b in _scan(machine).blind_spots)


def test_an_invented_name_in_quotes_falls_back_to_plain_words():
    text, from_model = N.narrate(GHOST, _Scripted(['The spirit of "mallory" haunts 4242.']))
    assert not from_model
    text, from_model = N.narrate(GHOST, _Scripted(["It's still here, as 4242 -- don't let it linger."]))
    assert from_model                                  # apostrophes aren't quotes


def test_an_empty_history_nobody_wrote_to_is_not_a_ghost(machine):
    """A fresh image or a cloud machine nobody has logged in to has an empty wtmp: only
    logins the auth log remembers make an empty history an erased one."""
    _w(machine, "/var/log/wtmp", b"")
    assert [g for g in _scan(machine).ghosts if g.kind == "memories"] == []
    _w(machine, "/var/log/auth.log", "Oct 27 09:00:01 web-01 CRON[90]: (root) CMD (true)\n")
    assert [g for g in _scan(machine).ghosts if g.kind == "memories"] == []
    _w(machine, "/var/log/auth.log", AUTH_WITH_LOGIN)
    [g] = [g for g in _scan(machine).ghosts if g.kind == "memories"]
    assert g.severity == "high" and g.evidence["logins_in_auth_log"] == 1


def test_a_young_container_is_not_judged_by_the_hosts_uptime(machine):
    """Inside a container /proc/uptime is the host's; the container's own age is its PID 1's."""
    started = int((time.time() - 60 - BOOT) * os.sysconf("SC_CLK_TCK"))
    _proc(machine, 1, "sh", "/usr/sbin/sshd", cmd="sh", start_ticks=started)
    _w(machine, "/var/log/wtmp", b"")
    _w(machine, "/var/log/auth.log", AUTH_WITH_LOGIN)
    assert [g for g in _scan(machine).ghosts if g.kind == "memories"] == []


def test_an_unreadable_auth_log_is_a_dark_spot_not_a_verdict(machine):
    if os.geteuid() == 0:
        pytest.skip("root reads it anyway")
    _w(machine, "/var/log/wtmp", b"")
    _w(machine, "/var/log/auth.log", AUTH_WITH_LOGIN, mode=0o000)
    s = _scan(machine)
    assert [g for g in s.ghosts if g.kind == "memories"] == []
    assert any("auth log couldn't be read" in b for b in s.blind_spots)

