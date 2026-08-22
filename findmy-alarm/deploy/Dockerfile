# findmy-alarm in a container -- for a NAS / homelab box that's always on.
#
# Build:
#   docker build -f deploy/Dockerfile -t findmy-alarm .
#
# Log in ONCE interactively (2FA needs a human), persisting the session to a volume:
#   docker run --rm -it -v findmy-data:/data \
#     -e FINDMY_APPLE_PASSWORD \
#     findmy-alarm login --email you@example.com --store-path /data/account.json
#
# Then run the alarm:
#   docker run -d --name findmy-alarm --restart unless-stopped \
#     -v findmy-data:/data \
#     -e FINDMY_APPLE_PASSWORD -e FINDMY_SMTP_PASSWORD \
#     findmy-alarm watch --config /data/config.yaml
#
# Secrets are passed as env vars (inherited from your shell, not baked in);
# /data holds account.json + alarm_state.json, both written 0600.

FROM python:3.12-slim

# libssl/ca-certificates for TLS to Apple + SMTP.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

# Run as a non-root user; /data is the only writable state.
RUN useradd --create-home --uid 10001 alarm \
    && mkdir -p /data \
    && chown -R alarm:alarm /data /app
USER alarm

VOLUME ["/data"]

ENTRYPOINT ["python", "-u", "/app/findmy_alarm.py"]
CMD ["--help"]
