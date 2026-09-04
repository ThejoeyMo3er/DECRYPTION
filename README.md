# File Configuration Processor

## Scope

The processing layer is intentionally limited to five formats whose algorithms are present in the referenced public source set: HTTP Injector, NPV Tunnel, HTTP Custom, Dark Tunnel and SSC Custom.

The user-facing interface accepts **files only**. There is no text/link extraction interface.

## Database compatibility

The existing path remains the same as the current bot: `${DATA_DIR}/prodecryptor.db`, with `/app/data/prodecryptor.db` as the default. Existing tables and rows are retained. New settings are additive and use `INSERT OR IGNORE`.

## Environment

- `BOT_TOKEN` — required.
- `DATA_DIR` — optional, defaults to `/app/data`.
- `NPVT_WHITEBOX_BLOB_FILE` — exact serialized white-box state for NPV Tunnel. If it is absent, NPV Tunnel is reported as unavailable rather than guessed or emulated with a substitute state.

## Install

```bash
pip install -r requirements.txt
python mainbot.py
```

## Docker

```bash
docker compose up -d --build
```

Put the exact NPV white-box blob at `/app/data/npvt_whitebox.b64` if NPV Tunnel support is required.

## Validation policy

A file is successful only when the detected format is enabled, its decrypt stage is enabled, the real parser succeeds, and any requested generated artifact passes validation. No placeholder credentials, guessed keys, or synthetic profiles are created.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile mainbot.py app/*.py app/decryptors/*.py
```

The repository does not invent live encrypted fixtures. The admin health screen therefore reports when a real fixture is absent. Supply real fixtures separately to test end-to-end decryptions.
