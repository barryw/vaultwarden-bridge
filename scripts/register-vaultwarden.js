#!/usr/bin/env node
/**
 * Register a test account on Vaultwarden and seed it with test items.
 * Uses Node.js crypto (same as bw CLI) to avoid key derivation mismatches.
 */

const crypto = require("crypto");
const http = require("http");
const { execFileSync } = require("child_process");

const VAULTWARDEN_URL = process.env.VAULTWARDEN_URL || "http://vaultwarden:80";
const EMAIL = process.env.TEST_EMAIL || "bridge-test@example.com";
const PASSWORD = process.env.TEST_PASSWORD || "TestPassword123!";
const KDF_ITERATIONS = 600000;

function pbkdf2(password, salt, iterations, keylen = 32) {
  return crypto.pbkdf2Sync(
    Buffer.from(password),
    Buffer.from(salt),
    iterations,
    keylen,
    "sha256"
  );
}

function hkdfExpand(prk, info, length) {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const okm = Buffer.alloc(length);
  let previousT = Buffer.alloc(0);

  for (let i = 0; i < n; i++) {
    const input = Buffer.concat([
      previousT,
      Buffer.from(info, "utf-8"),
      Buffer.from([i + 1]),
    ]);
    previousT = crypto.createHmac("sha256", prk).update(input).digest();
    previousT.copy(okm, i * hashLen);
  }
  return okm;
}

function encryptAesCbc(data, encKey, macKey) {
  const padLen = 16 - (data.length % 16);
  const padded = Buffer.concat([data, Buffer.alloc(padLen, padLen)]);

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
  cipher.setAutoPadding(false);
  const ct = Buffer.concat([cipher.update(padded), cipher.final()]);

  const mac = crypto
    .createHmac("sha256", macKey)
    .update(Buffer.concat([iv, ct]))
    .digest();

  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let responseBody = "";
        res.on("data", (chunk) => (responseBody += chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: responseBody })
        );
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function register() {
  const masterKey = pbkdf2(PASSWORD, EMAIL.toLowerCase(), KDF_ITERATIONS);
  const masterPasswordHash = pbkdf2(masterKey, PASSWORD, 1).toString("base64");

  const encKey = hkdfExpand(masterKey, "enc", 32);
  const macKey = hkdfExpand(masterKey, "mac", 32);

  const symKey = crypto.randomBytes(64);
  const encryptedSymKey = encryptAesCbc(symKey, encKey, macKey);

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });

  const publicKeyB64 = Buffer.from(publicKey).toString("base64");
  const userEncKey = symKey.subarray(0, 32);
  const userMacKey = symKey.subarray(32, 64);
  const encryptedPrivateKey = encryptAesCbc(
    Buffer.from(privateKey),
    userEncKey,
    userMacKey
  );

  const payload = {
    name: "Bridge Test",
    email: EMAIL,
    masterPasswordHash,
    masterPasswordHint: "test",
    key: encryptedSymKey,
    keys: {
      publicKey: publicKeyB64,
      encryptedPrivateKey,
    },
    kdf: 0,
    kdfIterations: KDF_ITERATIONS,
  };

  console.log("==> Registering account...");
  const resp = await httpPost(
    `${VAULTWARDEN_URL}/identity/accounts/register`,
    payload
  );

  if (resp.status === 200) {
    console.log("==> Account registered successfully");
  } else if (resp.status === 400 && resp.body.includes("already")) {
    console.log("==> Account may already exist");
  } else {
    console.error(`==> Registration failed (${resp.status}): ${resp.body}`);
    process.exit(1);
  }
}

function bw(args, env = {}) {
  try {
    return execFileSync("bw", args, {
      encoding: "utf-8",
      env: { ...process.env, BW_NOINTERACTION: "true", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

async function main() {
  bw(["config", "server", VAULTWARDEN_URL]);

  await register();

  console.log("==> Logging in...");
  let session = bw(["login", EMAIL, PASSWORD, "--raw"]);
  if (!session) {
    session = bw(["unlock", PASSWORD, "--raw"]);
  }
  if (!session) {
    console.error("ERROR: Could not get session");
    process.exit(1);
  }
  console.log("==> Login successful");

  console.log("==> Creating test items...");
  const items = [
    {
      type: 1,
      name: "prod/db/password",
      login: { username: "db_admin", password: "super-secret-db-password" },
    },
    {
      type: 1,
      name: "prod/api/token",
      login: { username: "api-service", password: "api-token-12345" },
    },
    {
      type: 1,
      name: "staging/db/password",
      login: { username: "db_staging", password: "staging-db-password" },
    },
    {
      type: 1,
      name: "denied-secret",
      login: { username: "nope", password: "you-shall-not-pass" },
    },
  ];

  for (const item of items) {
    const b64 = Buffer.from(JSON.stringify(item)).toString("base64");
    const result = bw(["create", "item", b64], { BW_SESSION: session });
    if (result) {
      console.log(`  Created: ${item.name}`);
    } else {
      console.error(`  Failed: ${item.name}`);
    }
  }

  bw(["sync"], { BW_SESSION: session });
  console.log(`==> Seeded ${items.length} test items`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
