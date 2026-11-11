// Criptografa os Member Resources com a senha (AES-GCM, chave via PBKDF2-SHA256).
// Uso:  node tools/encrypt-resources.mjs <senha> [arquivo.json]
// O arquivo JSON (padrão: tools/resources.private.json, ignorado pelo git) é uma lista de
// { title, desc, cta, href, color }. Cole o resultado em RESOURCES_BLOB no index.html.
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const [pw, file = new URL('./resources.private.json', import.meta.url)] = process.argv.slice(2);
if (!pw) { console.error('Uso: node tools/encrypt-resources.mjs <senha> [arquivo.json]'); process.exit(1); }
const data = JSON.stringify(JSON.parse(readFileSync(file, 'utf8')));
const ITER = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(data)));
const b64 = u => Buffer.from(u).toString('base64');
console.log(JSON.stringify({ iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
