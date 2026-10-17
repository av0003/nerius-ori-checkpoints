import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
const fail = message => { throw new Error(message); };
const sha256 = data => createHash('sha256').update(data).digest('hex');
const hex64 = value =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

function canonicalPayload(p) {
  if (!p || p.domain !== 'nerius.varium-ori.signed-checkpoint' ||
      p.version !== 1 || !Number.isSafeInteger(p.sequence) ||
      p.sequence < 1 || typeof p.createdAt !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(p.createdAt) ||
      !Number.isFinite(Date.parse(p.createdAt)) ||
      new Date(p.createdAt).toISOString() !== p.createdAt ||
      !hex64(p.signingKeyId) ||
      (p.previousCheckpointHash !== null &&
       !hex64(p.previousCheckpointHash))) {
    fail('Invalid checkpoint payload');
  }

  if ((p.sequence === 1) !== (p.previousCheckpointHash === null)) {
    fail('Invalid predecessor rule');
  }

  const s = p.state;

  if (!s || s.format !== 'nerius.varium-ori.checkpoint' ||
      s.version !== 1 || s.merkleAlgorithm !== 'sha256-binary-v1' ||
      s.leafOrder !== 'ori-id-ascending' ||
      s.leafEncoding !==
        'SHA256(0x00 || utf8(oriId) || 0x00 || raw32(chainTip))' ||
      s.parentEncoding !==
        'SHA256(0x01 || left32 || right32); duplicate last if odd' ||
      s.emptyRootEncoding !==
        'SHA256(utf8(nerius.varium-ori.checkpoint.empty.v1))' ||
      !hex64(s.merkleRoot)) {
    fail('Invalid Merkle checkpoint format');
  }

  for (const name of [
    'oriCount', 'neverTransferred', 'transferCount',
    'retrospectiveTransfers', 'contemporaneousTransfers'
  ]) {
    if (!Number.isSafeInteger(s[name]) || s[name] < 0) {
      fail(`Invalid count: ${name}`);
    }
  }

  if (s.neverTransferred > s.oriCount ||
      s.retrospectiveTransfers + s.contemporaneousTransfers !==
        s.transferCount) {
    fail('Inconsistent checkpoint counts');
  }

  return JSON.stringify({
    domain: p.domain,
    version: p.version,
    sequence: p.sequence,
    createdAt: p.createdAt,
    previousCheckpointHash: p.previousCheckpointHash,
    signingKeyId: p.signingKeyId,
    state: {
      format: s.format,
      version: s.version,
      merkleAlgorithm: s.merkleAlgorithm,
      leafOrder: s.leafOrder,
      leafEncoding: s.leafEncoding,
      parentEncoding: s.parentEncoding,
      emptyRootEncoding: s.emptyRootEncoding,
      oriCount: s.oriCount,
      neverTransferred: s.neverTransferred,
      transferCount: s.transferCount,
      retrospectiveTransfers: s.retrospectiveTransfers,
      contemporaneousTransfers: s.contemporaneousTransfers,
      merkleRoot: s.merkleRoot
    }
  });
}

try {
  const publicKey = createPublicKey(
    readFileSync(join(directory, 'checkpoint-public.pem'))
  );

  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail('Expected Ed25519 public key');
  }

  const keyId = sha256(
    publicKey.export({ type: 'spki', format: 'der' })
  );

  const expectedKeyId =
    '0b4edf3156a70a9ca9944ed29d213ff1a012a76e9b21f0223d1fe43cebe06269';

  if (keyId !== expectedKeyId) {
    fail('Public key fingerprint mismatch');
  }

  const files = readdirSync(directory)
    .filter(name => /^checkpoint-\d{6}\.json$/.test(name))
    .sort();

  if (!files.length) {
    fail('No checkpoints found');
  }

  let previousHash = null;

  for (let i = 0; i < files.length; i++) {
    const filename = files[i];
    const sequence = i + 1;

    const expectedFilename =
      `checkpoint-${String(sequence).padStart(6, '0')}.json`;

    if (filename !== expectedFilename) {
      fail(`Missing checkpoint ${sequence}`);
    }

    const checkpoint = JSON.parse(
      readFileSync(join(directory, filename), 'utf8')
    );

    const p = checkpoint.payload;

    if (!p || p.sequence !== sequence ||
        p.previousCheckpointHash !== previousHash) {
      fail(`${filename}: broken checkpoint chain`);
    }

    if (p.signingKeyId !== keyId) {
      fail(`${filename}: signing key mismatch`);
    }

    if (checkpoint.signatureAlgorithm !== 'Ed25519') {
      fail(`${filename}: unexpected signature algorithm`);
    }

    const hash = sha256(
      Buffer.from(canonicalPayload(p), 'utf8')
    );

    if (checkpoint.checkpointHash !== hash) {
      fail(`${filename}: checkpoint hash mismatch`);
    }

    if (typeof checkpoint.signature !== 'string' ||
        !/^[A-Za-z0-9+/]{86}==$/.test(checkpoint.signature)) {
      fail(`${filename}: invalid signature encoding`);
    }

    const signature = Buffer.from(
      checkpoint.signature, 'base64'
    );

    if (signature.length !== 64 ||
        signature.toString('base64') !== checkpoint.signature ||
        !verify(
          null,
          Buffer.from(hash, 'hex'),
          publicKey,
          signature
        )) {
      fail(`${filename}: invalid Ed25519 signature`);
    }

    console.log(`PASS: checkpoint ${sequence} verified`);
    previousHash = hash;
  }

  console.log(
    `PASS: ${files.length} signed checkpoints and chain links verified`
  );

} catch (error) {
  console.error('FAIL:', error.message);
  process.exitCode = 1;
}