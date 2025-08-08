import { promises as fs } from 'fs';
import * as path from 'path';

type Json = any;

const ROOT = path.resolve(__dirname, '..', 'bls12-381-tests', 'out', 'bls');

function isHexPrefixed(s: string) {
  return typeof s === 'string' && s.startsWith('0x') && /^[0-9a-fA-F]*$/.test(s.slice(2));
}

function hexLenBytes(s: string) {
  return (s.length - 2) / 2;
}

function checkPubkey(pk: string): string[] {
  const errs: string[] = [];
  if (!isHexPrefixed(pk)) errs.push('pubkey not hex');
  else if (![48, 96].includes(hexLenBytes(pk))) errs.push(`pubkey unexpected length ${hexLenBytes(pk)} bytes`);
  return errs;
}

function checkSignature(sig: string): string[] {
  const errs: string[] = [];
  if (!isHexPrefixed(sig)) errs.push('signature not hex');
  else if (hexLenBytes(sig) !== 96) errs.push(`signature unexpected length ${hexLenBytes(sig)} bytes`);
  return errs;
}

async function readJson(file: string): Promise<Json> {
  const raw = await fs.readFile(file, 'utf8');
  return JSON.parse(raw);
}

async function* walk(dir: string): AsyncGenerator<string> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile() && p.endsWith('.json')) yield p;
  }
}

async function validateFile(fp: string) {
  const rel = path.relative(ROOT, fp);
  const doc = await readJson(fp);
  const errs: string[] = [];

  function pushErr(s: string) { errs.push(`${rel}: ${s}`); }

  if (!doc || typeof doc !== 'object' || !('input' in doc)) pushErr('missing input');
  if (!('output' in doc)) pushErr('missing output');

  const input = doc.input || {};
  const output = doc.output;

  if (rel.includes('batch_verify')) {
    if (!Array.isArray(input.messages)) pushErr('messages not array');
    if (!Array.isArray(input.signatures)) pushErr('signatures not array');
    if (!Array.isArray(input.pubkeys)) pushErr('pubkeys not array');
    if (Array.isArray(input.messages) && Array.isArray(input.signatures) && Array.isArray(input.pubkeys)) {
      if (!(input.messages.length === input.signatures.length && input.signatures.length === input.pubkeys.length)) {
        pushErr('arrays lengths mismatch');
      }
    }
    if (typeof output !== 'boolean') pushErr('output not boolean');
    (input.signatures || []).forEach((s: string, i: number) => checkSignature(s).forEach(e => pushErr(`signatures[${i}]: ${e}`)));
    (input.pubkeys || []).forEach((pk: string, i: number) => checkPubkey(pk).forEach(e => pushErr(`pubkeys[${i}]: ${e}`)));
  }

  // aggregate: input is List[BLS Signature]
  else if (rel.includes('aggregate/') && !rel.includes('aggregate_verify')) {
    if (!Array.isArray(doc.input)) pushErr('input not array of signatures');
    (doc.input || []).forEach((s: string, i: number) => checkSignature(s).forEach(e => pushErr(`input[${i}]: ${e}`)));
    if (!(typeof output === 'string' && isHexPrefixed(output)) && output !== null) pushErr('output not hex or null');
    if (typeof output === 'string' && hexLenBytes(output) !== 96) pushErr(`output signature unexpected length ${hexLenBytes(output)} bytes`);
  }

  // sign: input has { privkey: bytes32, message: bytes32 }, output: signature|null
  else if (rel.includes('sign/')) {
    if (!isHexPrefixed(input.privkey) || hexLenBytes(input.privkey) !== 32) pushErr('privkey not bytes32');
    if (!isHexPrefixed(input.message) || hexLenBytes(input.message) !== 32) pushErr('message not bytes32');
    if (!(typeof output === 'string' && isHexPrefixed(output)) && output !== null) pushErr('output not hex or null');
    if (typeof output === 'string' && hexLenBytes(output) !== 96) pushErr(`output signature unexpected length ${hexLenBytes(output)} bytes`);
  }

  // verify: input has { pubkey: bytes48, message: bytes32, signature: bytes96 }, output: bool
  else if (rel.includes('verify/') && !rel.includes('aggregate_verify')) {
    checkPubkey(input.pubkey || '').forEach(e => pushErr(`pubkey: ${e}`));
    if (!isHexPrefixed(input.message) || hexLenBytes(input.message) !== 32) {
      if (output !== false) pushErr('message not bytes32');
    }
    {
      const errsSig = checkSignature(input.signature || '');
      if (errsSig.length && output !== false) errsSig.forEach(e => pushErr(`signature: ${e}`));
    }
    if (typeof output !== 'boolean') pushErr('output not boolean');
  }

  // fast_aggregate_verify: input has { pubkeys: List[bytes48], message: bytes32, signature: bytes96 }, output: bool
  else if (rel.includes('fast_aggregate_verify/')) {
    if (!Array.isArray(input.pubkeys)) pushErr('pubkeys not array');
    (input.pubkeys || []).forEach((pk: string, i: number) => checkPubkey(pk).forEach(e => pushErr(`pubkeys[${i}]: ${e}`)));
    if (!isHexPrefixed(input.message) || hexLenBytes(input.message) !== 32) {
      if (output !== false) pushErr('message not bytes32');
    }
    {
      const errsSig = checkSignature(input.signature || '');
      if (errsSig.length && output !== false) errsSig.forEach(e => pushErr(`signature: ${e}`));
    }
    if (typeof output !== 'boolean') pushErr('output not boolean');
  }

  // aggregate_verify: input has { pubkeys: List[bytes48], messages: List[bytes32], signature: bytes96 }, output: bool
  else if (rel.includes('aggregate_verify/')) {
    if (!Array.isArray(input.pubkeys)) pushErr('pubkeys not array');
    if (!Array.isArray(input.messages)) pushErr('messages not array');
    (input.pubkeys || []).forEach((pk: string, i: number) => checkPubkey(pk).forEach(e => pushErr(`pubkeys[${i}]: ${e}`)));
    (input.messages || []).forEach((m: string, i: number) => {
      if (!isHexPrefixed(m) || hexLenBytes(m) !== 32) {
        if (output !== false) pushErr(`messages[${i}]: not bytes32`);
      }
    });
    {
      const errsSig = checkSignature(input.signature || '');
      if (errsSig.length && output !== false) errsSig.forEach(e => pushErr(`signature: ${e}`));
    }
    if (typeof output !== 'boolean') pushErr('output not boolean');
  }

  // other categories (e.g., deserialization, hash_to_G2) are ignored by this checker

  return { rel, errs };
}

async function main() {
  const results: { rel: string; errs: string[] }[] = [];
  for await (const fp of walk(ROOT)) {
    const r = await validateFile(fp);
    results.push(r);
  }
  const failures = results.filter(r => r.errs.length);
  console.log(JSON.stringify({ total: results.length, failures: failures.length }, null, 2));
  if (failures.length) {
    for (const f of failures) {
      console.error(`\n# ${f.rel}`);
      f.errs.forEach(e => console.error(' - ' + e));
    }
    process.exitCode = 1;
  }
}

main().catch(e => { console.error(e); process.exit(1); });
