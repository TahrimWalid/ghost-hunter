"""ghosthunt -- the command line.

  ghosthunt                    hunt: scan this machine, then let the local model narrate
  ghosthunt scan --json        scan only, as JSON (no model; run it where the ghosts are)
  ghosthunt narrate FILE       narrate a scan taken elsewhere (run it where the model is)
  ghosthunt seance GHOST-ID    question one ghost; it answers only from its evidence
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from ghosthunt import __version__
from ghosthunt.checks import Ghost, Scan, scan
from ghosthunt.narrate import Model, ModelError, ask_ghost, narrate

DEPARTED_KINDS = ("home", "cron", "nameless")
ICONS = {"undead": "☠", "restless": "~", "bodiless": "◌", "hidden": "◐", "nameless": "?", "home": "⌂",
         "cron": "⧗", "possessed": "✶", "phantom": "◎", "memories": "⌫", "grave": "✝"}
SEV_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
BANNER = r"""
    .-.
   (o o)   G H O S T   H U N T E R
   | O \   what still walks on this machine
    \   \
     `~~~'
"""


def _color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _color() else text


def last_scan_path() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "ghosthunt" / "last-scan.json"


def save_scan(s: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)
    os.replace(tmp, path)


def load_scan(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("ghosts"), list):
        raise ValueError(f"{path} is not a Ghost Hunter scan")
    return data


def ghosts_of(data: dict) -> List[Ghost]:
    keys = ("id", "kind", "title", "severity", "evidence", "meaning", "next_step")
    return [Ghost(**{k: g[k] for k in keys}) for g in data["ghosts"] if all(k in g for k in keys)]


def _evidence_lines(g: Ghost) -> List[str]:
    out = []
    for k, v in g.evidence.items():
        val = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        out.append(f"      {k.replace('_', ' ')}: {val}")
    return out


def render(data: dict, voices: dict) -> str:
    ghosts = ghosts_of(data)
    lines = [_c(DIM, BANNER.rstrip()), ""]
    who = "as root" if data.get("as_root") else "as an ordinary user (some places stayed dark)"
    lines.append(f"Hunted {data.get('host', '?')} {who}.")
    if not ghosts:
        lines += ["", "No ghosts walked where Ghost Hunter could see.",
                  "That is not the same as none: see what stayed dark below."]
    living = [g for g in ghosts if g.kind not in DEPARTED_KINDS]
    departed = [g for g in ghosts if g.kind in DEPARTED_KINDS]
    for title, group in (("THE HAUNTINGS", living), ("OFRENDA -- for the accounts that are gone", departed)):
        if not group:
            continue
        lines += ["", _c(BOLD, title)]
        if group is departed:
            lines.append(_c(DIM, "  What departed accounts left behind. Lay them to rest properly: archive, then "
                                 "remove -- Ghost Hunter only recommends, it changes nothing."))
        for g in group:
            sev = _c(SEV_COLOR.get(g.severity, ""), g.severity.upper())
            lines += ["", f"  {ICONS.get(g.kind, '*')} {g.id}  {sev}  {g.title}"]
            lines += _evidence_lines(g)
            voice, from_model = voices.get(g.id, (None, False))
            if voice:
                tag = "the voice" if from_model else "Ghost Hunter"
                lines.append(f"    {_c(DIM, tag + ':')} {voice}")
            else:
                lines.append(f"    {g.meaning}")
                lines.append(f"    {_c(DIM, 'next:')} {g.next_step}")
    if data.get("blind_spots"):
        lines += ["", _c(BOLD, "WHAT STAYED DARK")]
        lines += [f"  - {b}" for b in data["blind_spots"]]
    lines += ["", _c(DIM, "Looked at: " + "; ".join(data.get("looked_at") or [])),
              _c(DIM, "Nothing was changed, killed, deleted or sent anywhere.")]
    if ghosts:
        lines.append(_c(DIM, f"Question a ghost: ghosthunt seance {ghosts[0].id}"))
    return "\n".join(lines)


def _voices(data: dict, model: Model, limit: int, say) -> dict:
    voices = {}
    ghosts = ghosts_of(data)[:limit]
    for i, g in enumerate(ghosts, 1):
        say(f"the voice speaks of {g.id} ({i}/{len(ghosts)})…")
        voices[g.id] = narrate(g, model)
    return voices


def cmd_hunt(args: argparse.Namespace) -> int:
    say = (lambda m: print(f"  {m}", file=sys.stderr)) if sys.stderr.isatty() else (lambda m: None)
    say("walking the machine…")
    data = scan(root=args.root, deep=args.deep).as_dict()
    save_scan(data, last_scan_path())
    voices = {} if args.no_voice else _voices(data, _model(args), args.max_voice, say)
    print(render(data, voices))
    return 1 if data["ghosts"] else 0


def cmd_scan(args: argparse.Namespace) -> int:
    data = scan(root=args.root, deep=args.deep).as_dict()
    save_scan(data, last_scan_path())
    text = json.dumps(data, indent=1)
    if args.output:
        save_scan(data, Path(args.output))
    elif args.json:
        print(text)
    else:
        print(render(data, {}))
    return 1 if data["ghosts"] else 0


def cmd_narrate(args: argparse.Namespace) -> int:
    data = load_scan(Path(args.file))
    save_scan(data, last_scan_path())
    say = (lambda m: print(f"  {m}", file=sys.stderr)) if sys.stderr.isatty() else (lambda m: None)
    print(render(data, _voices(data, _model(args), args.max_voice, say)))
    return 1 if data["ghosts"] else 0


def cmd_seance(args: argparse.Namespace) -> int:
    path = Path(args.from_file) if args.from_file else last_scan_path()
    try:
        data = load_scan(path)
    except (OSError, ValueError) as e:
        print(f"No scan to hold a séance with ({e}). Run `ghosthunt` or `ghosthunt scan` first.", file=sys.stderr)
        return 2
    by_id = {g.id.upper(): g for g in ghosts_of(data)}
    ghost = by_id.get(args.ghost.upper())
    if ghost is None:
        print(f"No ghost {args.ghost} in that scan. Ghosts: {', '.join(by_id) or 'none'}", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("A séance needs a person at a terminal.", file=sys.stderr)
        return 2
    model = _model(args)
    print(_c(DIM, f"The candles are lit for {ghost.id}: {ghost.title}."))
    print(_c(DIM, "Ask it anything. It answers only from what Ghost Hunter saw. Empty line to end."))
    history: List[dict] = []
    while True:
        try:
            q = input(_c(BOLD, "you> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q:
            break
        answer, trusted = ask_ghost(ghost, q, history, model)
        print(f"{ghost.id}> {answer}" if trusted else _c(DIM, answer))
        if trusted:
            history += [{"role": "user", "content": q}, {"role": "assistant", "content": answer}]
    print(_c(DIM, "The candles go out."))
    return 0


def _model(args: argparse.Namespace) -> Model:
    return Model(base_url=args.base_url, model=args.model, timeout=args.timeout)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ghosthunt", description="Find what is haunting a Linux machine -- "
                                "read-only -- and let a local open-weight model tell you about it.")
    p.add_argument("-V", "--version", action="version", version=f"ghosthunt {__version__}")
    p.add_argument("--model", help="model name (default: $GHOSTHUNT_MODEL or gemma3:4b)")
    p.add_argument("--base-url", help="OpenAI-compatible endpoint (default: $GHOSTHUNT_BASE_URL or local Ollama)")
    p.add_argument("--timeout", type=float, default=600.0, help="seconds to wait for one model reply")
    sub = p.add_subparsers(dest="command")
    hunt = sub.add_parser("hunt", help="scan this machine and narrate (the default)")
    sc = sub.add_parser("scan", help="scan only: no model")
    for x in (p, hunt, sc):
        x.add_argument("--deep", action="store_true", help="look for hidden processes at every possible PID")
        x.add_argument("--root", default="/", help=argparse.SUPPRESS)
    for x in (p, hunt):
        x.add_argument("--no-voice", action="store_true", help="skip the model; plain explanations only")
        x.add_argument("--max-voice", type=int, default=6, help="narrate at most this many ghosts (most serious first)")
    sc.add_argument("--json", action="store_true", help="print the scan as JSON")
    sc.add_argument("-o", "--output", help="write the scan as JSON to this file")
    na = sub.add_parser("narrate", help="narrate a scan taken elsewhere")
    na.add_argument("file")
    na.add_argument("--max-voice", type=int, default=6)
    se = sub.add_parser("seance", help="question one ghost from the last scan")
    se.add_argument("ghost")
    se.add_argument("--from", dest="from_file", help="a scan file (default: the last scan)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if sys.platform != "linux" and getattr(args, "root", "/") == "/" and args.command != "narrate":
        print("Ghost Hunter reads Linux's /proc; this isn't Linux.", file=sys.stderr)
        return 2
    handler = {None: cmd_hunt, "hunt": cmd_hunt, "scan": cmd_scan, "narrate": cmd_narrate,
               "seance": cmd_seance}[args.command]
    try:
        return handler(args)
    except ModelError as e:
        print(f"ghosthunt: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
