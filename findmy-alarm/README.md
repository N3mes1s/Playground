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

## Files it writes

- `account.json` — cached Apple session (contains credentials/tokens).
- `alarm_state.json` — per-object anchor and inside/outside state.

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
