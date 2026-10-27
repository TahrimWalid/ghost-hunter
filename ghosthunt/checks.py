"""The ghost checks: plain, read-only looks at a Linux machine. No model here.

Each check reads files under `root` (normally "/") and returns Ghosts -- things that
are present but shouldn't be, or that outlived what they belonged to. Nothing is
changed, killed or deleted, and nothing is sent anywhere. What a check could not read
(not root, a folder that isn't there) is recorded as a blind spot, never as "clean".
"""
from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Set, Tuple

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
MAX_TEMP_FILES = 2000          # per temp folder, so a flooded /tmp can't stall the hunt
SWEEP_MARGIN = 32768           # beyond the highest listed PID, by default
_LIBRARY = re.compile(r"\.so(\.\d+)*$")
CRON_SPOOLS = ("/var/spool/cron/crontabs", "/var/spool/cron", "/etc/crontabs")   # Debian, RHEL, Alpine
USER_WRITABLE = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/var/spool/", "/root/")
# Container runtimes run themselves from memory on purpose (runc's fix for CVE-2019-5736).
KNOWN_MEMFD = ("runc_cloned", "crun", "youki")


@dataclass
class Ghost:
    id: str                     # short and stable within one scan: UNDEAD-1, HOME-2 ...
    kind: str                   # undead | restless | bodiless | hidden | nameless | home | cron | possessed | phantom | memories | grave
    title: str                  # Ghost Hunter's own words, never machine text
    severity: str               # critical | high | medium | low
    evidence: Dict[str, object]
    meaning: str                # why it matters, in plain words (also the fallback narration)
    next_step: str              # what a person should check -- a recommendation, never run

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Scan:
    host: str
    root: str
    as_root: bool
    started: float
    finished: float = 0.0
    ghosts: List[Ghost] = field(default_factory=list)
    blind_spots: List[str] = field(default_factory=list)   # what could not be seen, in plain words
    looked_at: List[str] = field(default_factory=list)     # what was checked

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ghosts"] = [g.as_dict() for g in self.ghosts]
        return d


# --------------------------------------------------------------------------- reading
class Host:
    """Reads one machine's files under `root` (tests point it at a fake tree)."""

    def __init__(self, root: str = "/") -> None:
        self.root = root

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/")) if self.root != "/" else p

    def read(self, p: str, limit: int = 1 << 20) -> Optional[bytes]:
        """Regular files only (a FIFO or device planted where a file should be can't hang
        the scan), and no symlink followed in places users can write (a key file linked
        to /etc/shadow isn't read as keys)."""
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        if p.startswith(USER_WRITABLE):
            flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path(p), flags)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb") as f:
                fd = -1
                return f.read(limit)
        except OSError:
            return None
        finally:
            if fd >= 0:
                os.close(fd)

    def text(self, p: str, limit: int = 1 << 20) -> Optional[str]:
        b = self.read(p, limit)
        return None if b is None else b.decode("utf-8", "replace")

    def readlink(self, p: str) -> Optional[str]:
        try:
            return os.readlink(self.path(p))
        except OSError:
            return None

    def listdir(self, p: str) -> Optional[List[str]]:
        try:
            return os.listdir(self.path(p))
        except OSError:
            return None

    def lstat(self, p: str) -> Optional[os.stat_result]:
        try:
            return os.lstat(self.path(p))
        except OSError:
            return None

    def exists(self, p: str) -> bool:
        return os.path.lexists(self.path(p))


def clean(text: object, limit: int = 200) -> str:
    """Machine text made safe to show: no control characters, bounded."""
    s = str(text)
    s = "".join(ch if (ch.isprintable() and ch not in "‪‫‬‭‮⁦⁧⁨⁩")
                else "?" for ch in s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


class Accounts(dict):
    """uid -> account name. On the machine itself (root "/") a uid missing from
    /etc/passwd is also looked up the way the system does (NSS: LDAP, SSSD, ...), so a
    directory user isn't mistaken for a departed one."""

    def __init__(self, local: Dict[int, str], names: Dict[str, str], use_nss: bool) -> None:
        super().__init__(local)
        self.names = names            # name -> shell
        self.use_nss = use_nss

    def __missing__(self, uid: int) -> str:
        raise KeyError(uid)

    def __contains__(self, uid: object) -> bool:
        return self.get(uid) is not None

    def get(self, uid, default=None):  # type: ignore[override]
        if dict.__contains__(self, uid):
            return dict.__getitem__(self, uid)
        if self.use_nss and isinstance(uid, int):
            try:
                import pwd
                name = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError, OverflowError):
                name = None
            dict.__setitem__(self, uid, name)
            return name if name is not None else default
        return default

    def has_name(self, name: str) -> bool:
        if name in self.names:
            return True
        if self.use_nss:
            try:
                import pwd
                pwd.getpwnam(name)
                return True
            except (KeyError, ImportError):
                return False
        return False


def accounts(host: Host) -> Tuple[Accounts, Dict[str, str], bool]:
    """(uid -> name, name -> shell, readable) from /etc/passwd (+ NSS on this machine)."""
    by_uid: "Accounts" = {}
    shells: Dict[str, str] = {}
    txt = host.text("/etc/passwd")
    for line in (txt or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit():
            by_uid.setdefault(int(parts[2]), parts[0])
            shells[parts[0]] = parts[6]
    acc = Accounts(by_uid, shells, use_nss=host.root == "/")
    return acc, shells, txt is not None


@dataclass
class Proc:
    pid: int
    comm: str
    exe: Optional[str]          # the link target, None when it couldn't be read
    uid: Optional[int]
    ppid: Optional[int]
    cmdline: str
    started_ticks: Optional[int]


def read_proc(host: Host, pid: int) -> Optional[Proc]:
    status = host.text(f"/proc/{pid}/status", 1 << 16)
    if status is None:
        return None
    fields: Dict[str, str] = {}
    for line in status.splitlines():
        k, _, v = line.partition(":")
        fields[k] = v.strip()
    uid = None
    if fields.get("Uid"):
        try:
            uid = int(fields["Uid"].split()[0])
        except (ValueError, IndexError):
            uid = None
    ppid = int(fields["PPid"]) if fields.get("PPid", "").isdigit() else None
    raw = host.read(f"/proc/{pid}/cmdline", 4096) or b""
    cmd = clean(raw.replace(b"\0", b" ").decode("utf-8", "replace").strip(), 160)
    st = host.text(f"/proc/{pid}/stat", 4096) or ""
    ticks = None
    tail = st.rsplit(")", 1)[-1].split()
    if len(tail) > 19 and tail[19].isdigit():
        ticks = int(tail[19])
    return Proc(pid, clean(fields.get("Name", "?"), 40), host.readlink(f"/proc/{pid}/exe"), uid, ppid, cmd, ticks)


_CONTAINER_CGROUP = ("lxc.payload", "/docker", "docker-", "libpod", "containerd", "kubepods", "/lxc/", "machine.slice")


def subid_ranges(host: Host) -> List[Tuple[int, int]]:
    """User-id ranges handed to containers (/etc/subuid): their processes look ownerless
    from the host but belong to a container's own accounts."""
    out = []
    for line in (host.text("/etc/subuid") or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
            out.append((int(parts[1]), int(parts[1]) + int(parts[2])))
    return out


def in_container(host: Host, pid: int, uid: Optional[int], ranges: List[Tuple[int, int]]) -> bool:
    cg = host.text(f"/proc/{pid}/cgroup", 4096) or ""
    if any(m in cg for m in _CONTAINER_CGROUP):
        return True
    return uid is not None and any(lo <= uid < hi for lo, hi in ranges)


def listed_pids(host: Host) -> Set[int]:
    return {int(n) for n in (host.listdir("/proc") or []) if n.isdigit()}


def _boot_time(host: Host) -> Optional[float]:
    for line in (host.text("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return None


def _started(host: Host, p: Proc) -> Optional[str]:
    bt = _boot_time(host)
    if bt is None or p.started_ticks is None:
        return None
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(bt + p.started_ticks / hz))


def _started_after(host: Host, p: Proc, when: float) -> bool:
    bt = _boot_time(host)
    if bt is None or p.started_ticks is None:
        return False
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    return bt + p.started_ticks / hz >= when - 1


def _proc_evidence(host: Host, p: Proc, by_uid: "Accounts") -> Dict[str, object]:
    ev: Dict[str, object] = {"pid": p.pid, "name": p.comm, "command": p.cmdline or "(none)"}
    if p.uid is not None:
        ev["user"] = by_uid.get(p.uid, f"uid {p.uid} (no such account)")
    if p.ppid is not None:
        ev["parent_pid"] = p.ppid
    started = _started(host, p)
    if started:
        ev["started"] = started
    return ev


# --------------------------------------------------------------------------- the checks
def check_processes(host: Host, scan: Scan, by_uid: "Accounts", deep: bool) -> None:
    """Undead (deleted program still running), bodiless (memory only), nameless (owned by
    no account) and hidden (missing from the /proc listing) processes."""
    scan.looked_at.append("running processes")
    mounts = host.text("/proc/mounts", 1 << 16) or ""
    proc_opts = next((ln.split()[3] for ln in mounts.splitlines() if len(ln.split()) > 3 and ln.split()[1] == "/proc"),
                     "")
    if not scan.as_root and ("hidepid=" in proc_opts or "subset=pid" in proc_opts):
        scan.blind_spots.append("/proc is mounted with hidepid: other users' processes are invisible here "
                                "(run as root to see them)")
    pids = listed_pids(host)
    ranges = subid_ranges(host)
    unreadable = contained = 0
    for pid in sorted(pids):
        p = read_proc(host, pid)
        if p is None:
            continue
        if in_container(host, pid, p.uid, ranges):
            contained += 1         # a container's own process: hunt inside that container
            continue
        if p.exe is None:
            if p.cmdline:          # a kernel thread has neither; a user process we may not read
                unreadable += 1
        elif p.exe.startswith("/memfd:") and p.exe[7:].startswith(KNOWN_MEMFD):
            scan.ghosts.append(Ghost(
                "", "bodiless", "A container runtime running from memory, as it is meant to", "low",
                {**_proc_evidence(host, p, by_uid), "program": clean(p.exe)},
                "Container runtimes such as runc copy themselves into memory before starting a container -- the "
                "fix for CVE-2019-5736. This one carries such a runtime's name.",
                "Nothing to do if this machine runs containers; if it doesn't, look closer."))
        elif p.exe.startswith("/memfd:"):     # "/memfd:name (deleted)": never had a file
            scan.ghosts.append(Ghost(
                "", "bodiless", "A program running with no file at all, from memory only", "high",
                {**_proc_evidence(host, p, by_uid), "program": clean(p.exe)},
                "Its program was loaded into memory and never existed as a file on disk -- a common way to run "
                "malware without leaving anything to scan.",
                f"Look at what started it (parent process {p.ppid}) and at its network connections; "
                f"copy its memory image from /proc/{pid}/exe before stopping it."))
        elif p.exe.endswith(" (deleted)"):
            path = p.exe[: -len(" (deleted)")]
            if host.exists(path):
                scan.ghosts.append(Ghost(
                    "", "restless", "A program still running the old code of a file that has since been replaced",
                    "low", {**_proc_evidence(host, p, by_uid), "program": clean(path)},
                    "A new file now sits at the same path, which usually means a package update: the process "
                    "keeps running the old code until it restarts.",
                    "Restart this service so it runs the updated program."))
            else:
                scan.ghosts.append(Ghost(
                    "", "undead", "A program still running after its file was deleted", "high",
                    {**_proc_evidence(host, p, by_uid), "program": clean(path)},
                    "Its file is gone but it keeps running -- attackers delete their tools after starting them "
                    "so nothing is left on disk to find.",
                    f"Copy its program from /proc/{pid}/exe before anything else, then find out what started it."))
        if p.uid is not None and p.uid not in by_uid:
            scan.ghosts.append(Ghost(
                "", "nameless", "A process running as a user that has no account", "high",
                _proc_evidence(host, p, by_uid),
                "Every process should belong to an account in /etc/passwd. One that doesn't was started with a "
                "raw user id or outlived its account.",
                "Find out who started it and why no account owns that user id."))
    if unreadable:
        scan.blind_spots.append(f"{unreadable} process(es) belong to other users and couldn't be inspected "
                                "(run as root to see them)")
    if contained:
        scan.blind_spots.append(f"{contained} process(es) run inside containers and were left to them "
                                "(run Ghost Hunter inside a container to hunt there)")
    # hidden: a process that answers by number but is missing from the /proc listing
    pid_max = int((host.text("/proc/sys/kernel/pid_max") or "4194304").strip() or 4194304)
    top = pid_max if deep else min(pid_max, (max(pids) if pids else 0) * 2 + SWEEP_MARGIN)
    for pid in range(1, top + 1):
        if pid in pids or host.lstat(f"/proc/{pid}") is None:
            continue
        status = host.text(f"/proc/{pid}/status", 1 << 16) or ""
        tgid = next((ln.split(":", 1)[1].strip() for ln in status.splitlines() if ln.startswith("Tgid:")), "")
        if tgid != str(pid):
            continue          # a thread of a listed process: /proc/<tid> exists but is never listed
        p = read_proc(host, pid)
        if p is None or in_container(host, pid, p.uid, ranges):
            continue
        # a process born after the listing isn't hiding: look again, and by its start time
        if pid in listed_pids(host) or _started_after(host, p, scan.started):
            continue
        scan.ghosts.append(Ghost(
            "", "hidden", "A process that hides from the process list", "critical",
            _proc_evidence(host, p, by_uid),
            "It is running but left out of the /proc listing that ps and top read. Programs don't do that on "
            "their own: something on this machine is hiding it, which is what rootkits do.",
            "Treat the machine as compromised: check /etc/ld.so.preload and loaded kernel modules, and "
            "investigate from a trusted system."))
    if not deep and top < pid_max:
        scan.blind_spots.append(f"hidden processes were looked for up to PID {top:,} of {pid_max:,} "
                                "(--deep looks at all of them)")


def check_departed(host: Host, scan: Scan, by_uid: "Accounts", shells: Dict[str, str]) -> None:
    """What departed accounts left behind: homes, SSH keys and cron jobs."""
    scan.looked_at.append("homes, SSH keys and cron jobs of accounts")
    for name in sorted(host.listdir("/home") or []):
        home = f"/home/{name}"
        st = host.lstat(home)
        if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid in by_uid:
            continue
        keys = host.text(f"{home}/.ssh/authorized_keys", 1 << 16)
        n_keys = sum(1 for ln in (keys or "").splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
        ev: Dict[str, object] = {"home": clean(home), "owner_uid": st.st_uid, "account": "none"}
        if keys is not None:
            ev["ssh_keys"] = n_keys
        if n_keys:
            scan.ghosts.append(Ghost(
                "", "home", "SSH keys left behind by an account that no longer exists", "high", ev,
                "The account is gone but its keys remain. If anyone recreates an account with that user id, or "
                "the keys are copied elsewhere, they open a door for someone who should have left.",
                f"Archive and remove {home}/.ssh/authorized_keys, and check whether those keys are used on other "
                "machines."))
        else:
            scan.ghosts.append(Ghost(
                "", "home", "A home folder whose account no longer exists", "medium", ev,
                "Its owner was removed but the files stayed. A new account given the same user id would inherit "
                "them.", f"Archive {home} and remove it, or give it a clear owner."))
    for spool in CRON_SPOOLS:
        names = host.listdir(spool)
        if names is None:
            if host.exists(spool):
                scan.blind_spots.append(f"users' cron jobs in {spool} couldn't be read (run as root)")
            continue
        for name in sorted(names):
            st = host.lstat(f"{spool}/{name}")
            if st is None or not stat.S_ISREG(st.st_mode) or name.startswith(".") or by_uid.has_name(name):
                continue
            _orphan_cron(scan, spool, name)


def _orphan_cron(scan: Scan, spool: str, name: str) -> None:
    scan.ghosts.append(Ghost(
        "", "cron", "A scheduled job for an account that no longer exists", "high",
        {"crontab": clean(f"{spool}/{name}"), "account": clean(name, 40)},
        "Cron keeps a schedule for a name with no account behind it: whatever it runs was set up by someone "
        "who is gone, or by someone who wanted it to look that way.",
        f"Read {spool}/{name} to see what it runs, then remove it."))


def check_possession(host: Host, scan: Scan) -> None:
    """A library forced into every program: /etc/ld.so.preload."""
    scan.looked_at.append("libraries forced into every program (/etc/ld.so.preload)")
    txt = host.text("/etc/ld.so.preload")
    if not txt:
        return
    libs = [clean(x) for x in txt.split() if x.strip() and not x.startswith("#")]
    if libs:
        scan.ghosts.append(Ghost(
            "", "possessed", "Every program on this machine is made to load an extra library", "critical",
            {"file": "/etc/ld.so.preload", "libraries": libs},
            "Anything listed in /etc/ld.so.preload is loaded into every program that starts. Rootkits use it to "
            "hide files, processes and connections from the tools you would use to find them.",
            "Check which package owns each library listed; a library no package owns is a strong sign of a "
            "rootkit -- investigate from a trusted system."))


def check_phantom_ports(host: Host, scan: Scan, as_root: bool) -> None:
    """Listening sockets that no visible process holds."""
    scan.looked_at.append("listening network ports")
    listening: List[Tuple[str, int, str]] = []        # (proto, port, inode)
    for proto, f in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), ("udp", "/proc/net/udp"),
                     ("udp6", "/proc/net/udp6")):
        for line in (host.text(f) or "").splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10:
                continue
            state, inode = cols[3], cols[9]
            if (proto.startswith("tcp") and state != "0A") or (proto.startswith("udp") and state != "07"):
                continue
            try:
                port = int(cols[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if inode != "0":
                listening.append((proto, port, inode))
    if not listening:
        return
    if not as_root:
        scan.blind_spots.append("which program owns each listening port couldn't be checked (run as root)")
        return
    held: Set[str] = set()
    for pid in listed_pids(host):
        for fd in host.listdir(f"/proc/{pid}/fd") or []:
            target = host.readlink(f"/proc/{pid}/fd/{fd}") or ""
            if target.startswith("socket:["):
                held.add(target[8:-1])
    for proto, port, inode in sorted(set(listening)):
        if inode not in held:
            scan.ghosts.append(Ghost(
                "", "phantom", "A port is open but no process admits to holding it", "high",
                {"protocol": proto, "port": port, "socket_inode": inode},
                "Something is listening for connections, yet no process on the list owns the socket. Hidden "
                "processes or kernel-level tricks are the usual explanations.",
                f"Connect to port {port} from another machine to see what answers, and look for hidden "
                "processes."))


AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
_LOGIN_LINE = ("Accepted password for", "Accepted publickey for", "session opened for user")


def _machine_age(host: Host) -> float:
    """How long this machine (or container) has been up: from its own PID 1, since
    /proc/uptime inside a container reports the host's uptime."""
    p1 = read_proc(host, 1)
    bt = _boot_time(host)
    if p1 is not None and p1.started_ticks is not None and bt is not None:
        hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        return max(0.0, time.time() - (bt + p1.started_ticks / hz))
    up = (host.text("/proc/uptime") or "0").split()
    return float(up[0]) if up else 0.0


def _logins_in_auth_log(host: Host) -> Optional[int]:
    """Logins the auth log still records (None: no auth log could be read)."""
    found = None
    for f in AUTH_LOGS:
        st = host.lstat(f)
        if st is None:
            continue
        raw = host.read(f, 8 << 20)
        if raw is None:
            continue
        txt = raw.decode("utf-8", "replace")
        found = (found or 0) + sum(1 for ln in txt.splitlines() if any(k in ln for k in _LOGIN_LINE))
    return found


def check_memories(host: Host, scan: Scan) -> None:
    """A login history that was erased: the auth log still shows logins, but the login
    history (wtmp, or wtmpdb on newer systems) is missing or empty. An empty history on
    a machine nobody has logged in to is normal -- not a ghost."""
    scan.looked_at.append("the login history (wtmp / wtmpdb) against the auth log")
    if _machine_age(host) < 3600:
        return
    db = host.lstat("/var/lib/wtmpdb/wtmp.db")
    wtmp = host.lstat("/var/log/wtmp")
    hist_file = "/var/lib/wtmpdb/wtmp.db" if db is not None else "/var/log/wtmp"
    hist = db if db is not None else wtmp
    if hist is not None and hist.st_size > 0:
        return
    logins = _logins_in_auth_log(host)
    if logins is None:
        if any(host.exists(f) for f in AUTH_LOGS):
            scan.blind_spots.append("the auth log couldn't be read, so an erased login history couldn't be "
                                    "told apart from one nobody wrote to (run as root)")
        return
    if logins == 0:
        return
    state = "missing" if hist is None else "empty"
    scan.ghosts.append(Ghost(
        "", "memories", f"The login history is {state}, but the auth log remembers logins", "high",
        {"file": hist_file, "present": hist is not None, "logins_in_auth_log": logins},
        "The auth log still records people logging in, yet the login history that should list them has been "
        f"{'removed' if hist is None else 'emptied'}. Erasing it is a classic way to hide who was here.",
        "Compare the auth log's logins with what `last` shows, and find out when the history was cleared."))


def check_graves(host: Host, scan: Scan, by_uid: "Accounts") -> None:
    """Programs left in temporary folders, especially ones owned by no account."""
    scan.looked_at.append("programs left in temporary folders")
    for d in TEMP_DIRS:
        stack, seen = [d], 0
        while stack and seen < MAX_TEMP_FILES:
            cur = stack.pop()
            for name in host.listdir(cur) or []:
                seen += 1
                p = f"{cur}/{name}"
                st = host.lstat(p)
                if st is None:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(p)
                    continue
                if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or _LIBRARY.search(name):
                    continue          # shared libraries: build tools and unpackers leave plenty in /tmp
                head = host.read(p, 4) or b""
                if head[:4] != b"\x7fELF":
                    continue
                owner = by_uid.get(st.st_uid)
                scan.ghosts.append(Ghost(
                    "", "grave", "A compiled program left in a temporary folder", "high" if owner is None else "medium",
                    {"file": clean(p), "owner": owner or f"uid {st.st_uid} (no such account)",
                     "size_bytes": st.st_size, "modified": time.strftime("%Y-%m-%d %H:%M UTC",
                                                                         time.gmtime(st.st_mtime))},
                    "Ready-to-run programs rarely belong in temporary folders; downloaded attack tools often wait "
                    "there.", f"Find out what {clean(p)} is (its hash, which process ran it) before removing it."))


CHECKS = ("processes", "departed", "possession", "phantom", "memories", "graves")


def scan(root: str = "/", deep: bool = False, host_name: Optional[str] = None) -> Scan:
    host = Host(root)
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    name = host_name or clean((host.text("/proc/sys/kernel/hostname") or "this machine").strip(), 64)
    s = Scan(host=name, root=root, as_root=as_root, started=time.time())
    by_uid, shells, readable = accounts(host)
    if not readable:
        s.blind_spots.append("/etc/passwd couldn't be read, so accounts couldn't be checked")
    check_processes(host, s, by_uid, deep)
    check_departed(host, s, by_uid, shells)
    check_possession(host, s)
    check_phantom_ports(host, s, as_root)
    check_memories(host, s)
    check_graves(host, s, by_uid)
    s.ghosts.sort(key=lambda g: (SEVERITY_ORDER.get(g.severity, 9), g.kind))
    counters: Dict[str, int] = {}
    for g in s.ghosts:
        prefix = g.kind.upper()
        counters[prefix] = counters.get(prefix, 0) + 1
        g.id = f"{prefix}-{counters[prefix]}"
    s.finished = time.time()
    return s
