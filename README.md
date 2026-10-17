# Varium Ori — Public Checkpoint Registry

This repository contains publicly verifiable cryptographic checkpoints for Varium Ori, a digital collectible associated with the Nerius / Mission Window game.

Its purpose is to provide an independently accessible record of the collection's cryptographic history.

## What is a checkpoint?

Each checkpoint represents a snapshot of the Varium Ori collection at a particular point in time.

A checkpoint includes:

- A SHA-256 Merkle root representing the collection state.
- The number of Oris and recorded ownership transfers.
- A sequential checkpoint number and creation timestamp.
- The cryptographic hash of the previous checkpoint, where applicable.
- An Ed25519 digital signature.

Together, these provide a verifiable sequence of signed collection snapshots.

## Verify the checkpoints

You need Node.js installed on your computer.

Clone this repository:

```bash
git clone https://github.com/av0003/nerius-ori-checkpoints.git
cd nerius-ori-checkpoints
```

Run the independent verifier:

```bash
node verify-checkpoints.mjs
```

For the first two checkpoints, the expected output is:

```text
PASS: checkpoint 1 verified
PASS: checkpoint 2 verified
PASS: 2 signed checkpoints and chain links verified
```

The verifier checks:

- Checkpoint hashes against their canonical payloads.
- Ed25519 signatures against the published public key.
- The public key against the registry's initial trusted fingerprint.
- Sequential numbering and cryptographic links between checkpoints.
- Checkpoint format and internal count consistency.

The verifier uses Node.js's built-in cryptography library. It does not require access to the Nerius game server, database, or private signing keys.

## Repository files

| File | Purpose |
|---|---|
| `checkpoint-000001.json` | First signed checkpoint |
| `checkpoint-000002.json` | Second signed checkpoint |
| `checkpoint-public.pem` | Public Ed25519 verification key |
| `verify-checkpoints.mjs` | Standalone verification script |

Additional checkpoints may be published as the collection changes.

## What verification proves

Successful verification establishes that the available checkpoint records have valid signatures, match their recorded hashes, and form a correctly linked sequence under the published verification key.

It does not independently establish:

- That the original game data was accurate.
- That every ownership transfer was legitimate.
- That no checkpoint has been withheld or omitted from the published history.
- That the repository's history has never been rewritten.
- That the signing key belongs to a particular organisation without independent authentication.

The Merkle root commits to a collection state, but this repository does not currently provide the underlying collection data or individual Ori inclusion proofs.

## Public key and trust

The initial public-key fingerprint (SHA-256 of the DER/SPKI-encoded key) is:

```text
0b4edf3156a70a9ca9944ed29d213ff1a012a76e9b21f0223d1fe43cebe06269
```

For stronger protection against historical rewriting, checkpoint hashes should also be retained or anchored independently of this GitHub repository.

## Current status

This is the initial public checkpoint registry. Independent cryptographic verification is operational; stronger external timestamping and anchoring are planned.
