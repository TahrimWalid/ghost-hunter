# Ghost Hunter

Find what still walks on a Linux machine after it should have gone — and let a small,
local, open-weight model tell you about it.

```
    .-.
   (o o)   G H O S T   H U N T E R
   | O \   what still walks on this machine
    \   \
     `~~~'
```

Ghost Hunter looks for the things that outlive what they belonged to:

| Ghost | What it is | Why it matters |
|---|---|---|
| **undead** | a program still running after its file was deleted | attackers delete their tools after starting them |
| **bodiless** | a program running from memory only, never a file | a common way to run malware with nothing on disk to scan |
| **hidden** | a process left out of the `/proc` listing | something on the machine is hiding it — what rootkits do |
| **nameless** | a process running as a user id with no account | started with a raw user id, or outlived its account |
| **possessed** | a library forced into every program (`/etc/ld.so.preload`) | how userland rootkits hide files and processes |
| **phantom** | a listening port no process admits to holding | hidden processes or kernel tricks |
| **memories** | a login history that is missing or empty | erasing it hides a break-in |
| **grave** | a compiled program left in `/tmp`, `/var/tmp` or `/dev/shm` | downloaded tools often wait there |

And because it is the season of the Day of the Dead, it keeps an **ofrenda** for the accounts
that are gone: the home folders, SSH keys and cron jobs they left behind. A departed
account's key is a door left open for someone who should have left.

## It only looks

Ghost Hunter changes nothing: it doesn't kill, delete or "clean" anything, and the scan
sends nothing anywhere. Every ghost comes with what to check next — a recommendation for
a person, never something it runs. When it can't see somewhere (not run as root, `/proc`
mounted with `hidepid`, processes inside containers), it says so under **What stayed dark**:
"no ghosts" is never presented as "clean".

## The voice

The checks are plain code: they decide what is a ghost. A local open-weight model only
**narrates** — what it is, why it matters, what to do — in a voice suited to the season.

The model can't make things up and get away with it. Before a narration is shown,
Ghost Hunter checks every path, number, address and quoted name in it against that ghost's
evidence. Anything that isn't there means the model invented it, and Ghost Hunter shows its
own plain explanation instead. Process names and command lines come from the machine — an
attacker can write them — so they reach the model only as data inside a JSON block, and
are cleaned of control characters before they reach your terminal.

## The séance

```
ghosthunt seance UNDEAD-1
```

Question a ghost. It answers in the first person, only from what Ghost Hunter saw. Ask it
something its evidence doesn't hold and it says *"That, I do not remember."* An answer that
quotes anything the evidence doesn't contain is withheld.

## Running it

Python 3.8 or newer, Linux, nothing else to install for the scan.

```bash
pip install git+https://github.com/TahrimWalid/ghost-hunter
ghosthunt scan              # the checks only, no model
sudo ghosthunt scan         # as root it sees every process and port
```

For the voice, run any OpenAI-compatible endpoint with an open-weight model. With
[Ollama](https://ollama.com):

```bash
ollama pull gemma3:4b
ghosthunt                   # scan, then narrate (the most serious ghosts first)
ghosthunt seance HOME-1
```

Other models and endpoints: `--model`, `--base-url` (or `GHOSTHUNT_MODEL`,
`GHOSTHUNT_BASE_URL`). On a CPU only, a 4B model can take a minute or two per ghost;
`--max-voice` limits how many are narrated, and a GPU makes it near-instant.

**Scan here, narrate there.** A server rarely has a model on it. Scan it with nothing
leaving the machine, then narrate the file where your model runs:

```bash
sudo ghosthunt scan -o ghosts.json        # on the server
ghosthunt narrate ghosts.json             # on your laptop
```

## Limits

- Linux only (it reads `/proc`).
- A kernel-level rootkit can lie to `/proc` itself; Ghost Hunter catches the userland kind
  and the tells others leave. For a machine you suspect, look from a trusted system.
- The hidden-process sweep covers the PIDs in use; `--deep` covers every possible PID
  (about 15 seconds).
- It checks the machine it runs on. Inside a container it hunts that container.

## Where it comes from

Ghost Hunter was built for Hacktoberfest 2026 (week 4, *Ghost in the Machine*) by the author
of [Kratos](https://github.com/TahrimWalid/kratos), an observe-and-recommend security
assistant for Linux servers. It borrows Kratos's two rules: **plain checks decide, the model
only explains** — and **never act on a machine without a person**.

## License

MIT
