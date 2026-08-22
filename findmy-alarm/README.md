# findmy-alarm

A **geofence departure alarm** for Apple Find My objects (AirTags and other Find
My accessories) on Linux. Point it at an object, give it your email, and it
emails you the moment the object moves away from where it started — like arming
a real alarm.

This is a generalization of the workflow described in
[*Find My people on Linux*](https://zerotistic.blog/posts/find-my-people-linux/).
That post reverse-engineers Apple's GrandSlam login, IDS registration, and
SearchParty report decryption by hand. Here we lean on
[**FindMy.py**](https://github.com/malmeloo/FindMy.py), which implements exactly
that pipeline (anisette headers, ECDH/ECDSA, AES-GCM report decryption), and
wrap it in a small, config-driven alarm so you can *just pass your email*.

## What it does

```
             ┌── login (once) ──► account.json  (cached Apple session)
             │
  Apple ID ──┤                        ┌─────────────────────────────┐
  (email)    └── watch (loop) ──► fetch_location(object) via FindMy.py
                                       │ decrypts the latest report  │
                                       └──────────────┬──────────────┘
                                                      ▼
                          ┌──────────── geofence check ────────────┐
                          │ distance(current, anchor) > radius ?    │
                          └──────────────┬──────────────────────────┘
                                         ▼  (on inside→outside edge)
                                   email alarm  ──►  your inbox
```

- **Anchor**: the "home" spot the object should stay near. Either you set it
  (`lat,lon`) or the first location fix is captured automatically.
- **Radius**: how far it may drift before it counts as *moving* (meters).
- **Edge-triggered**: you get one alarm when it crosses the fence, not a stream.
  It re-arms when the object comes back inside. Optional `renotify` re-alerts on
  a cooldown while it stays away.
- **Notifications**: email over SMTP. For gmail / icloud / outlook / yahoo the
  SMTP server is inferred from your address, so you only supply an app password.

## Install

```bash
pip install -r requirements.txt
```

> FindMy.py needs to generate Apple "anisette" validation data. By default this
> uses its built-in local provider. If that gives you trouble, run an anisette
> server and pass `--anisette-server http://host:port`.

## Getting the object's keys

FindMy.py needs the accessory's decryption keys to read its reports. Two ways:

- **`.plist`** dumped from the Find My app / iCloud for the accessory
  (an AirTag you own). Pass it with `--plist keys-airtag.plist`. The tool derives
  the rolling keys automatically.
- **Base64 private key** for a custom tag you flashed yourself. Pass it with
  `--key-b64 ...`.

## Usage

Secrets come from the environment, never the command line:

```bash
export FINDMY_APPLE_PASSWORD='your-apple-id-password'   # app-specific password recommended
export FINDMY_SMTP_PASSWORD='your-email-app-password'   # for sending mail
```

**1. Log in once** (handles SMS / trusted-device 2FA, caches the session):

```bash
python findmy_alarm.py login --email you@gmail.com
```

**2. Arm the alarm** — the simplest single-object case is just your email, the
object, and a radius:

```bash
python findmy_alarm.py watch --email you@gmail.com --plist keys-airtag.plist --radius 150
```

The first fetch captures the current spot as the anchor and arms. From then on,
if the object drifts more than 150 m away, you get an email.

**One-shot check** (no loop):

```bash
python findmy_alarm.py status --email you@gmail.com --plist keys-airtag.plist
```

**Dry run** (print alarms to the console instead of emailing):

```bash
python findmy_alarm.py watch --email you@gmail.com --plist keys-airtag.plist --radius 150 --dry-run
```

### Watching several objects

Use a YAML config (copy `config.example.yaml` → `config.yaml`):

```bash
python findmy_alarm.py watch --config config.yaml
```

Each object gets its own anchor, radius, and key source. See the example file
for all options (anisette server, poll interval, re-notify cooldown, explicit
SMTP host for non-consumer domains, etc.).

## Common options

| Flag | Meaning | Default |
|------|---------|---------|
| `--email` | Apple ID email (also default notify address) | — |
| `--plist` / `--key-b64` | Object key source | — |
| `--radius` | Geofence radius (meters) | 100 |
| `--anchor "lat,lon"` | Fixed anchor instead of auto-capture | auto |
| `--interval` | Poll interval (seconds) | 300 |
| `--renotify` | Re-alert every N s while away (0 = off) | 0 |
| `--notify-to` | Send alarms to a different address | `--email` |
| `--smtp-host` / `--smtp-port` | Override inferred SMTP server | inferred |
| `--anisette-server` | Remote anisette provider URL | local |
| `--dry-run` | Console instead of email | off |

## Security — how not to leak the world

This tool handles three things worth protecting: your **Apple session**, the
object's **private keys**, and your **live location**. Here's how to run it
without leaking any of them.

**What the sensitive files are**

| File | Contains | Risk if leaked |
|------|----------|----------------|
| `account.json` | Apple session tokens (login-equivalent) | Full access to your Apple account's Find My |
| `*.plist` / `--key-b64` | The accessory's decryption keys | Anyone with these can track that tag forever |
| `alarm_state.json` | Your anchor coordinates ("home") | Reveals where you live/park |
| `config.yaml` | May inline passwords if you put them there | Credentials |

The tool writes `account.json` and `alarm_state.json` as **`0600`
(owner-only)**, and all four names are in `.gitignore` — so a stray
`git add .` won't commit them. Keep it that way; don't `git add -f` them.

**Secrets stay out of the command line and out of git**

- Pass passwords via environment variables, never as flags (flags show up in
  `ps` and shell history):
  ```bash
  export FINDMY_APPLE_PASSWORD='...'
  export FINDMY_SMTP_PASSWORD='...'
  ```
- Use an **app-specific password** for both Apple (appleid.apple.com → Sign-In
  and Security) and your mail provider, not your real account password. Then a
  leak is revocable and scoped, and it works with 2FA on.
- Prefer keeping passwords in the env (or a `.env` you don't commit) rather than
  inline in `config.yaml`. If you must inline them, `chmod 600 config.yaml`.

**Don't send your location through a third party**

- **Anisette**: by default the tool uses FindMy.py's *local* provider, so the
  Apple validation data is generated on your machine. Only pass
  `--anisette-server` if you run that server **yourself** — a public anisette
  server sees device-identifying validation data. Don't point it at a random
  host.
- **Email**: alarms contain exact coordinates and a map link. They go over
  TLS (STARTTLS/SSL) in transit, but your mail provider can read the body at
  rest. Send alarms **only to yourself** (the default). If that's still too
  much exposure, run with `--dry-run` (console only) or add a self-hosted
  webhook/ntfy notifier instead of email.

**Run it where only you can reach it**

- Run on a single-user host or your own account; the `0600` files assume you're
  not sharing the box. On a shared machine, put the working dir under a
  `chmod 700` directory.
- If you daemonize it (systemd), load secrets from an `EnvironmentFile` that is
  itself `0600` and root/owner-only — not from the unit file.

**If something leaks**

- Leaked `account.json` or Apple password → change your Apple ID password /
  revoke the app-specific password; the session tokens die with it.
- Leaked `.plist` / key → that tag is compromised for tracking; re-pair the
  AirTag to your account to roll its keys.

## Files it writes

- `account.json` — cached Apple session (contains credentials/tokens), `0600`.
- `alarm_state.json` — per-object anchor and inside/outside state, `0600`.

Both are git-ignored. **Treat `account.json` and any `.plist` as secrets.**

## Layout

```
findmy_alarm.py     CLI + watch loop (login / status / watch)
findmy_compat.py    version-tolerant imports over FindMy.py
geofence.py         haversine distance + edge-triggered alarm state
notifier.py         SMTP email (+ console), provider auto-detection
config.py           YAML + quick-flag configuration model
test_geofence.py    offline tests for the alarm logic (no Apple needed)
config.example.yaml sample multi-object config
```

## Tests

The alarm/geofence logic is testable without any Apple account or network:

```bash
python test_geofence.py
```

## Notes & limitations

- Report freshness depends on when a nearby iPhone last relayed the object's
  beacon — a tag in a drawer can be minutes to hours stale. Set `--interval`
  and `--radius` accordingly; this is a "left the area" alarm, not real-time GPS.
- Use an **app-specific password** for your Apple ID where possible, and keep
  `FINDMY_APPLE_PASSWORD` / `FINDMY_SMTP_PASSWORD` out of your shell history.
- Only watch objects you own or are authorized to locate.
