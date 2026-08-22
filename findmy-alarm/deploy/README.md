# Deploying findmy-alarm

Run this on a machine you own that **stays powered on** — Raspberry Pi, NAS,
home server, small VPS. A laptop that sleeps is a disarmed alarm.

Whichever route you pick, do the interactive login **once** first, on that
machine — 2FA needs a human:

```bash
python findmy_alarm.py login --email you@example.com
```

Then verify your mail path works before you rely on it (sends a real email):

```bash
python findmy_alarm.py watch --email you@example.com --simulate --radius 100 --interval 2
```

## Options

- **`findmy-alarm.service`** — systemd *user* unit. Secrets come from a `0600`
  `EnvironmentFile`, not the unit; restart-on-failure is rate-limited so a
  crash-loop can't hammer Apple. Install steps are in the file's header.
- **`Dockerfile`** — non-root container, state on a `/data` volume, secrets via
  env vars. Build/run commands are in the file's header.

## Status

These two files were written against the documented behavior of systemd and
Docker but **could not be executed in the environment where they were
authored** (no systemd manager, no Docker daemon). Treat them as starting
points: expect to adjust paths (`WorkingDirectory`, `%h`, the config location)
for your box, and check `journalctl --user -u findmy-alarm -f` or
`docker logs -f findmy-alarm` on first run.

The application itself *is* verified — the geofence logic has offline tests
(`python test_geofence.py`) and the full fetch → geofence → notify path runs
under `--simulate`.
