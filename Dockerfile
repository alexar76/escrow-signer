FROM python:3.12-slim

# No build tooling in the final image: eth-account ships wheels for this platform, and a
# compiler in the container that holds the signing key is a gift to anyone who lands in it.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY escrow_signer ./escrow_signer

# The ledger lives on a volume: it is the record of what this key has spent, and losing it
# means losing every cap window and every idempotency guarantee at once.
#
# The directory is created AND chowned here, before VOLUME, because docker seeds a fresh named
# volume from the image path — including its ownership. Without this the volume arrives
# root-owned, the container runs as 65534, SQLite cannot create its file, and the service
# refuses to start with `ledger unavailable`. Which is the correct refusal, and a useless one:
# it never signs and never says why in a way an operator can act on.
RUN mkdir -p /var/lib/escrow-signer && chown -R 65534:65534 /var/lib/escrow-signer
VOLUME ["/var/lib/escrow-signer"]
ENV SIGNER_DB_PATH=/var/lib/escrow-signer/signer.db

# Loopback only. This service is reached through an SSH tunnel from the hub host; it must
# never be published to an interface, and there is no configuration in this image that
# would make that safe.
ENV SIGNER_BIND_HOST=0.0.0.0 SIGNER_BIND_PORT=9500
EXPOSE 9500

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import json,urllib.request,sys; d=json.loads(urllib.request.urlopen('http://127.0.0.1:9500/health',timeout=4).read()); sys.exit(0 if d.get('ok') else 1)"

USER 65534:65534
ENTRYPOINT ["python", "-m", "escrow_signer"]
