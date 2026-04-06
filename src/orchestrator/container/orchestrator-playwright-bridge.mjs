#!/usr/bin/env node

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chromium } from "playwright-core";

const DEFAULT_SOCKET_PATH = "/run/orchestrator-playwright-bridge.sock";
const HOST_TRUST_ROOT = "/host-trust";
const ORCHESTRATOR_TMP_ROOT = "/tmp/orchestrator";

function parseArgs(argv) {
  const args = {
    sessionId: null,
    idleSeconds: 45,
    action: null,
    extract: null,
    success: null,
    ping: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--session-id") {
      i += 1;
      args.sessionId = argv[i] || null;
    } else if (arg === "--idle-seconds") {
      i += 1;
      const parsed = Number.parseInt(argv[i] || "", 10);
      if (Number.isFinite(parsed) && parsed > 0) {
        args.idleSeconds = parsed;
      }
    } else if (arg === "--action") {
      i += 1;
      args.action = argv[i] || null;
    } else if (arg === "--extract") {
      i += 1;
      args.extract = argv[i] || null;
    } else if (arg === "--success") {
      i += 1;
      args.success = argv[i] || null;
    } else if (arg === "--ping") {
      args.ping = true;
    }
  }

  return args;
}

function socketPath() {
  return process.env.ORCHESTRATOR_BRIDGE_SOCKET || DEFAULT_SOCKET_PATH;
}

function browserExecutablePath() {
  return process.env.PLAYWRIGHT_CHROMIUM || undefined;
}

function redactUrlForLog(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl));
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch (_error) {
    return "<invalid-url>";
  }
}

function ignoreHttpsErrors() {
  const value = process.env.ORCHESTRATOR_IGNORE_HTTPS_ERRORS;
  if (!value) {
    return false;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function browserEnv(baseEnv, trust) {
  const env = {
    ...baseEnv,
    HOME: trust.homeDir,
    XDG_CONFIG_HOME: trust.xdgConfigHome,
    XDG_DATA_HOME: trust.xdgDataHome,
  };

  const useProxy = ["1", "true", "yes"].includes(
    String(process.env.ORCHESTRATOR_USE_PROXY || "").toLowerCase()
  );

  if (!useProxy) {
    delete env.HTTP_PROXY;
    delete env.HTTPS_PROXY;
    delete env.ALL_PROXY;
    delete env.http_proxy;
    delete env.https_proxy;
    delete env.all_proxy;
    delete env.NO_PROXY;
    delete env.no_proxy;
  }

  return env;
}

function sessionSafeName(sessionId) {
  return String(sessionId || "session").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function certDerToPem(rawDer) {
  const b64 = rawDer.toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function extractCertificatesFromBuffer(buffer) {
  const certs = [];
  const text = buffer.toString("utf8");
  const pemPattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const pemMatches = text.match(pemPattern);

  if (pemMatches && pemMatches.length > 0) {
    for (const pem of pemMatches) {
      try {
        const x509 = new X509Certificate(pem);
        certs.push({
          fingerprint: x509.fingerprint256,
          pem: certDerToPem(x509.raw),
          isCa: x509.ca,
        });
      } catch (_error) {
        // Skip non-certificate PEM blocks.
      }
    }
    return certs;
  }

  try {
    const x509 = new X509Certificate(buffer);
    certs.push({
      fingerprint: x509.fingerprint256,
      pem: certDerToPem(x509.raw),
      isCa: x509.ca,
    });
  } catch (_error) {
    // Not a parseable DER certificate.
  }

  return certs;
}

function walkFiles(rootPath, maxDepth = 6) {
  const files = [];
  if (!fs.existsSync(rootPath)) {
    return files;
  }

  const queue = [{ path: rootPath, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(current.path, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current.path, entry.name);
      if (entry.isDirectory()) {
        if (current.depth < maxDepth) {
          queue.push({ path: fullPath, depth: current.depth + 1 });
        }
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

function collectHostCertificates() {
  const certificates = new Map();
  const certFiles = walkFiles(HOST_TRUST_ROOT);
  process.stderr.write(`Host trust scan: ${certFiles.length} files under ${HOST_TRUST_ROOT}\n`);

  for (const filePath of certFiles) {
    let content;
    try {
      content = fs.readFileSync(filePath);
    } catch (_error) {
      continue;
    }

    if (content.length === 0 || content.length > 2 * 1024 * 1024) {
      continue;
    }

    const extracted = extractCertificatesFromBuffer(content);
    for (const cert of extracted) {
      if (!certificates.has(cert.fingerprint)) {
        certificates.set(cert.fingerprint, cert);
      }
    }
  }

  return Array.from(certificates.values());
}

function runCommand(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    throw new Error(`${command} ${args.join(" ")} failed: ${stderr}`);
  }
}

function prepareChromiumTrust(sessionId) {
  const safeSession = sessionSafeName(sessionId);
  const sessionRoot = path.join(ORCHESTRATOR_TMP_ROOT, "sessions", safeSession);
  const homeDir = path.join(sessionRoot, "home");
  const profileDir = path.join(sessionRoot, "profile");
  const xdgConfigHome = path.join(homeDir, ".config");
  const xdgDataHome = path.join(homeDir, ".local", "share");
  const nssDbDir = path.join(homeDir, ".pki", "nssdb");
  const certTempDir = path.join(sessionRoot, "cert-import");
  const nssPwFile = path.join(sessionRoot, "nss-password.txt");

  fs.mkdirSync(profileDir, { recursive: true });
  fs.mkdirSync(xdgConfigHome, { recursive: true });
  fs.mkdirSync(xdgDataHome, { recursive: true });
  fs.mkdirSync(nssDbDir, { recursive: true });
  fs.mkdirSync(certTempDir, { recursive: true });
  fs.writeFileSync(nssPwFile, "\n");

  let imported = 0;
  try {
    if (!fs.existsSync(path.join(nssDbDir, "cert9.db"))) {
      runCommand("certutil", ["-N", "-d", `sql:${nssDbDir}`, "-f", nssPwFile]);
    }

    const certs = collectHostCertificates();
    process.stderr.write(`Host trust parse: ${certs.length} certificates discovered\n`);
    for (const cert of certs) {
      const certFile = path.join(certTempDir, `${cert.fingerprint}.pem`);
      fs.writeFileSync(certFile, cert.pem);
      const trustFlags = cert.isCa ? "C,," : "P,,";
      runCommand("certutil", [
        "-A",
        "-d",
        `sql:${nssDbDir}`,
        "-f",
        nssPwFile,
        "-n",
        cert.fingerprint,
        "-t",
        trustFlags,
        "-i",
        certFile,
      ]);
      imported += 1;
    }
    process.stderr.write(`Chromium trust import: ${imported} certificates imported\n`);
  } catch (error) {
    process.stderr.write(`Failed preparing Chromium trust: ${String(error)}\n`);
  }

  return {
    homeDir,
    profileDir,
    xdgConfigHome,
    xdgDataHome,
    importedCount: imported,
  };
}

async function sendRequest(request) {
  const target = socketPath();
  return await new Promise((resolve, reject) => {
    let settled = false;
    let output = "";

    const socket = net.createConnection(target);
    socket.setEncoding("utf8");

    socket.on("connect", () => {
      socket.write(JSON.stringify(request));
      socket.end();
    });

    socket.on("data", (chunk) => {
      output += chunk;
    });

    socket.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });

    socket.on("close", () => {
      if (settled) {
        return;
      }
      settled = true;
      if (!output.trim()) {
        reject(new Error("bridge returned an empty response"));
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch (error) {
        reject(new Error(`failed to parse bridge response: ${error}`));
      }
    });
  });
}

async function runServer(sessionId, idleSeconds) {
  process.umask(0o077);

  const target = socketPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  try {
    fs.unlinkSync(target);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  const trust = prepareChromiumTrust(sessionId);
  if (trust.importedCount > 0) {
    process.stderr.write(`Imported ${trust.importedCount} host certificates for Chromium trust\n`);
  }

  const browser = await chromium.launch({
    headless: true,
    executablePath: browserExecutablePath(),
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--no-proxy-server",
      "--proxy-bypass-list=*",
    ],
    env: browserEnv(process.env, trust),
  });
  const allowInsecureTls = ignoreHttpsErrors();
  if (allowInsecureTls) {
    process.stderr.write(
      "WARNING: ORCHESTRATOR_IGNORE_HTTPS_ERRORS is enabled; TLS certificate validation is disabled\n"
    );
  }
  const context = await browser.newContext({
    ignoreHTTPSErrors: allowInsecureTls,
  });
  const page = await context.newPage();

  let idleTimer = null;
  let shuttingDown = false;

  const cleanup = async () => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    if (idleTimer) {
      clearTimeout(idleTimer);
    }
    try {
      await context.close();
    } catch (_error) {
      // no-op
    }
    try {
      await browser.close();
    } catch (_error) {
      // no-op
    }
    try {
      fs.unlinkSync(target);
    } catch (_error) {
      // no-op
    }
  };

  const resetIdleTimer = () => {
    if (idleTimer) {
      clearTimeout(idleTimer);
    }
    idleTimer = setTimeout(async () => {
      await cleanup();
      process.exit(0);
    }, Math.max(1, idleSeconds) * 1000);
  };

  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    let data = "";
    socket.setEncoding("utf8");

    socket.on("error", (error) => {
      process.stderr.write(`Bridge client socket error: ${String(error)}\n`);
    });

    socket.on("data", (chunk) => {
      data += chunk;
    });

    socket.on("end", async () => {
      let response;
      try {
        const request = JSON.parse(data);
        response = await handleRequest(page, request);
        resetIdleTimer();
      } catch (error) {
        response = { ok: false, error: String(error) };
      }

      if (socket.destroyed) {
        return;
      }

      try {
        socket.end(JSON.stringify(response));
      } catch (error) {
        process.stderr.write(`Failed sending bridge response: ${String(error)}\n`);
      }
    });
  });

  process.on("SIGTERM", async () => {
    await cleanup();
    process.exit(0);
  });
  process.on("SIGINT", async () => {
    await cleanup();
    process.exit(0);
  });

  await new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(target, () => {
      try {
        fs.chmodSync(target, 0o600);
      } catch (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  resetIdleTimer();

  // Keep alive until terminated.
  const _sessionId = sessionId;
  void _sessionId;
  await new Promise(() => {});
}

async function handleRequest(page, request) {
  if (!request || typeof request !== "object") {
    throw new Error("invalid request payload");
  }

  if (request.command === "action") {
    return await handleAction(page, request.payload);
  }
  if (request.command === "extract") {
    return await handleExtract(page, request.source);
  }
  if (request.command === "success") {
    return await handleSuccess(page, request.success);
  }
  if (request.command === "ping") {
    return { ok: true, pong: true };
  }

  throw new Error(`unsupported command '${request.command}'`);
}

async function handleAction(page, payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("missing action payload");
  }

  if (payload.action === "navigate") {
    if (typeof payload.url !== "string" || payload.url.length === 0) {
      throw new Error("navigate action requires url");
    }
    const response = await page.goto(payload.url, {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });
    const status = response ? response.status() : null;
    const sanitizedUrl = redactUrlForLog(page.url());
    process.stderr.write(
      `Bridge navigate result: url=${sanitizedUrl} status=${status === null ? "null" : String(status)}\n`
    );
    return { ok: true };
  }

  if (payload.action === "fill") {
    await page.fill(payload.selector, payload.value, { timeout: 15000 });
    return { ok: true };
  }

  if (payload.action === "click") {
    await page.click(payload.selector, { timeout: 15000 });
    return { ok: true };
  }

  throw new Error(`unsupported action '${payload.action}'`);
}

async function handleExtract(page, source) {
  if (typeof source !== "string" || source.length === 0) {
    throw new Error("extract requires a non-empty source");
  }

  let value = null;
  if (source.startsWith("browser:query:")) {
    const key = source.slice("browser:query:".length);
    const current = new URL(page.url());
    value = current.searchParams.get(key);
  } else if (source.startsWith("browser:storage:")) {
    const key = source.slice("browser:storage:".length);
    value = await page.evaluate((storageKey) => {
      const local = window.localStorage.getItem(storageKey);
      if (local !== null) {
        return local;
      }
      return window.sessionStorage.getItem(storageKey);
    }, key);
  } else if (source === "browser:url") {
    value = page.url();
  } else if (source === "browser:title") {
    value = await page.title();
  }

  return { ok: true, value: value === undefined ? null : value };
}

async function handleSuccess(page, success) {
  if (!success || typeof success !== "object") {
    throw new Error("success probe requires a payload");
  }

  let matches = true;

  if (typeof success.url_contains === "string" && success.url_contains.length > 0) {
    matches = page.url().includes(success.url_contains);
  }

  if (typeof success.dom_selector === "string" && success.dom_selector.length > 0) {
    const visible = await page.evaluate((selector) => {
      const isVisible = (element) => {
        if (!element) {
          return false;
        }
        const style = window.getComputedStyle(element);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
          return false;
        }
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      };
      const node = document.querySelector(selector);
      return isVisible(node);
    }, success.dom_selector);
    matches = visible;
  }

  return { ok: true, success: matches };
}

async function runClient(parsedArgs) {
  if (parsedArgs.action) {
    const payload = JSON.parse(parsedArgs.action);
    const response = await sendRequest({ command: "action", payload });
    ensureOk(response);
    return;
  }

  if (parsedArgs.extract) {
    const response = await sendRequest({ command: "extract", source: parsedArgs.extract });
    ensureOk(response);
    if (response.value === null || response.value === undefined || response.value === "") {
      process.stdout.write("null\n");
    } else {
      process.stdout.write(`${String(response.value)}\n`);
    }
    return;
  }

  if (parsedArgs.success) {
    const success = JSON.parse(parsedArgs.success);
    const response = await sendRequest({ command: "success", success });
    ensureOk(response);
    process.stdout.write(`${response.success ? "true" : "false"}\n`);
    return;
  }

  if (parsedArgs.ping) {
    const response = await sendRequest({ command: "ping" });
    ensureOk(response);
    process.stdout.write("pong\n");
    return;
  }

  throw new Error("no command specified");
}

function ensureOk(response) {
  if (!response || response.ok !== true) {
    const reason = response && response.error ? response.error : "unknown bridge failure";
    throw new Error(reason);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.sessionId) {
    await runServer(args.sessionId, args.idleSeconds);
    return;
  }

  await runClient(args);
}

main().catch((error) => {
  process.stderr.write(`${String(error)}\n`);
  process.exit(1);
});
