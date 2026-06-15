#!/usr/bin/env node

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { chromium } from "playwright-core";

const DEFAULT_SOCKET_PATH = "/run/orchestrator-playwright-bridge.sock";
const HOST_TRUST_ROOT = "/host-trust";
const ORCHESTRATOR_TMP_ROOT = "/tmp/orchestrator";
const TRUST_CACHE_ROOT = path.join(ORCHESTRATOR_TMP_ROOT, "trust-cache");

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

function trustDebugEnabled() {
  return ["1", "true", "yes", "on"].includes(
    String(process.env.ORCHESTRATOR_DEBUG_TRUST || "").toLowerCase()
  );
}

function debugTrust(message) {
  if (trustDebugEnabled()) {
    process.stderr.write(`${message}\n`);
  }
}

function proxyEnabled() {
  return ["1", "true", "yes"].includes(
    String(process.env.ORCHESTRATOR_USE_PROXY || "").toLowerCase()
  );
}

function firstProxyEnv(...names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && String(value).trim()) {
      return String(value).trim();
    }
  }
  return null;
}

function browserProxy() {
  if (!proxyEnabled()) {
    return undefined;
  }

  const server = firstProxyEnv(
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy"
  );
  if (!server) {
    return undefined;
  }

  const proxy = { server };
  const bypass = firstProxyEnv("NO_PROXY", "no_proxy");
  if (bypass) {
    proxy.bypass = bypass;
  }
  return proxy;
}

function chromiumLaunchArgs() {
  const args = [
    // Running with Chrome sandbox disabled is a compatibility tradeoff for
    // rootful container runtimes that do not provide user namespaces in all
    // target distributions. Mitigations:
    // - Container drops all Linux capabilities (`--cap-drop=ALL`)
    // - `no-new-privileges` is enabled by default
    // - Read-only rootfs + isolated tmpfs runtime
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
  ];

  if (!proxyEnabled()) {
    args.push("--no-proxy-server", "--proxy-bypass-list=*");
  }

  return args;
}

function browserEnv(baseEnv, trust) {
  const env = {
    ...baseEnv,
    HOME: trust.homeDir,
    XDG_CONFIG_HOME: trust.xdgConfigHome,
    XDG_DATA_HOME: trust.xdgDataHome,
  };

  if (!proxyEnabled()) {
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
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index];
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
  debugTrust(`Host trust scan: ${certFiles.length} files under ${HOST_TRUST_ROOT}`);

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

function trustCacheKey(certs) {
  const hash = createHash("sha256");
  for (const cert of certs) {
    hash.update(cert.fingerprint);
    hash.update(cert.isCa ? "ca" : "leaf");
    hash.update("\n");
  }
  return hash.digest("hex");
}

function copyDirectoryContents(source, target) {
  fs.mkdirSync(target, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    if (entry.isDirectory()) {
      fs.cpSync(sourcePath, targetPath, { recursive: true });
    } else if (entry.isFile()) {
      fs.copyFileSync(sourcePath, targetPath);
    }
  }
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
    const certs = collectHostCertificates();
    debugTrust(`Host trust parse: ${certs.length} certificates discovered`);

    const cacheKey = trustCacheKey(certs);
    const cacheDir = path.join(TRUST_CACHE_ROOT, cacheKey);
    if (fs.existsSync(path.join(cacheDir, "cert9.db"))) {
      copyDirectoryContents(cacheDir, nssDbDir);
      debugTrust(`Chromium trust cache hit: ${cacheKey}`);
    } else {
      const stagingDir = `${cacheDir}.tmp-${process.pid}`;
      fs.rmSync(stagingDir, { recursive: true, force: true });
      fs.mkdirSync(stagingDir, { recursive: true });
      runCommand("certutil", ["-N", "-d", `sql:${stagingDir}`, "-f", nssPwFile]);

      for (const cert of certs) {
        const certFile = path.join(certTempDir, `${cert.fingerprint}.pem`);
        fs.writeFileSync(certFile, cert.pem);
        const trustFlags = cert.isCa ? "C,," : "P,,";
        runCommand("certutil", [
          "-A",
          "-d",
          `sql:${stagingDir}`,
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

      fs.rmSync(cacheDir, { recursive: true, force: true });
      fs.renameSync(stagingDir, cacheDir);
      copyDirectoryContents(cacheDir, nssDbDir);
      debugTrust(`Chromium trust cache populated: ${imported} certificates imported`);
    }
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
  debugTrust(`Chromium trust ready: imported=${trust.importedCount}`);

  const browser = await chromium.launch({
    headless: true,
    executablePath: browserExecutablePath(),
    args: chromiumLaunchArgs(),
    env: browserEnv(process.env, trust),
    proxy: browserProxy(),
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

  const exitAfterCleanup = async () => {
    const forceExit = setTimeout(() => {
      process.exit(0);
    }, 1000);
    forceExit.unref();
    await cleanup();
    process.exit(0);
  };

  process.on("SIGTERM", () => {
    void exitAfterCleanup();
  });
  process.on("SIGINT", () => {
    void exitAfterCleanup();
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
  if (request.command === "inspect_page") {
    return await handleInspectPage(page);
  }
  if (request.command === "wait_for_settle") {
    await waitForSettle(page);
    return { ok: true };
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
    await waitForSettle(page);
    return { ok: true };
  }

  if (payload.action === "submit_form") {
    const submitted = await page.evaluate((selector) => {
      const element = document.querySelector(selector);
      if (!element) {
        return false;
      }
      const form = element.closest("form");
      if (!form) {
        return false;
      }
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
      } else {
        form.submit();
      }
      return true;
    }, payload.selector);
    if (!submitted) {
      await page.press(payload.selector, "Enter", { timeout: 15000 });
    }
    await waitForSettle(page);
    return { ok: true };
  }

  throw new Error(`unsupported action '${payload.action}'`);
}

async function waitForSettle(page) {
  try {
    await page.waitForLoadState("domcontentloaded", { timeout: 5000 });
  } catch (_error) {
    // DOM may already be settled or the page may be a single-page app.
  }
  try {
    await page.waitForTimeout(500);
  } catch (_error) {
    // no-op
  }
}

async function handleInspectPage(page) {
  const value = await page.evaluate(() => {
    const textOf = (value, max = 240) =>
      String(value || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, max);

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

    const cssEscape = (value) => {
      if (window.CSS && typeof window.CSS.escape === "function") {
        return window.CSS.escape(value);
      }
      return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
    };

    const selectorFor = (element, stableId) => {
      if (stableId) {
        element.setAttribute("data-himmelblau-orchestrator-id", stableId);
        return `[data-himmelblau-orchestrator-id="${stableId}"]`;
      }
      if (element.id) {
        return `#${cssEscape(element.id)}`;
      }
      const name = element.getAttribute("name");
      if (name) {
        const tag = element.tagName.toLowerCase();
        return `${tag}[name="${String(name).replace(/"/g, '\\"')}"]`;
      }
      const all = Array.from(document.querySelectorAll(element.tagName.toLowerCase()));
      const index = all.indexOf(element);
      return `${element.tagName.toLowerCase()}:nth-of-type(${index + 1})`;
    };

    const labelFor = (element) => {
      const id = element.id;
      if (id) {
        const explicit = document.querySelector(`label[for="${cssEscape(id)}"]`);
        if (explicit) {
          return textOf(explicit.innerText || explicit.textContent);
        }
      }
      const wrapping = element.closest("label");
      if (wrapping) {
        return textOf(wrapping.innerText || wrapping.textContent);
      }
      return "";
    };

    const browserError = () => {
      const selectors = [
        "#kc-error-message",
        "body[data-page-id*='error' i] #kc-error-message",
        "body[data-page-id*='error' i] main",
        "[role='alert']",
        "[aria-live='assertive']",
        ".alert-danger",
        ".pf-m-danger",
        "[id*='error' i]",
        "[class*='error' i]",
      ];
      for (const selector of selectors) {
        for (const element of Array.from(document.querySelectorAll(selector))) {
          if (!isVisible(element)) {
            continue;
          }
          const text = textOf(element.innerText || element.textContent, 600);
          if (text) {
            return text;
          }
        }
      }
      return "";
    };

    const actionFrom = (element, index) => ({
      id: `action-${index}`,
      selector: selectorFor(element, `action-${index}`),
      text: textOf(element.innerText || element.textContent || element.getAttribute("value")),
      kind: textOf(element.getAttribute("type") || element.getAttribute("role") || element.tagName.toLowerCase(), 64),
    });

    const fieldFrom = (element, index) => ({
      id: `field-${index}`,
      selector: selectorFor(element, `field-${index}`),
      tag: element.tagName.toLowerCase(),
      input_type: textOf(element.getAttribute("type") || "", 64).toLowerCase(),
      name: textOf(element.getAttribute("name") || "", 128),
      autocomplete: textOf(element.getAttribute("autocomplete") || "", 128).toLowerCase(),
      id_attr: textOf(element.getAttribute("id") || "", 128),
      label: labelFor(element),
      placeholder: textOf(element.getAttribute("placeholder") || "", 160),
      aria_label: textOf(element.getAttribute("aria-label") || "", 160),
      required:
        element.hasAttribute("required") ||
        element.getAttribute("aria-required") === "true",
    });

    const fieldSelector =
      "input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='reset']), textarea, select, [contenteditable='true']";
    const actionSelector =
      "button, input[type='submit'], input[type='button'], input[type='reset'], a[role='button']";

    const allFields = Array.from(document.querySelectorAll(fieldSelector)).filter(
      (element) => isVisible(element) && !element.disabled && !element.readOnly
    );
    const allActions = Array.from(document.querySelectorAll(actionSelector)).filter(
      (element) => isVisible(element) && !element.disabled
    );

    const fieldIds = new Map();
    allFields.forEach((field, index) => fieldIds.set(field, `field-${index}`));
    const actionIds = new Map();
    allActions.forEach((action, index) => actionIds.set(action, `action-${index}`));

    const forms = Array.from(document.querySelectorAll("form"))
      .filter((form) => isVisible(form))
      .map((form, formIndex) => {
        const fields = allFields
          .filter((field) => form.contains(field))
          .map((field) => fieldFrom(field, Number(fieldIds.get(field).slice("field-".length))));
        const actions = allActions
          .filter((action) => form.contains(action))
          .map((action) => actionFrom(action, Number(actionIds.get(action).slice("action-".length))));
        return {
          id: `form-${formIndex}`,
          text: textOf(form.innerText || form.textContent, 1000),
          fields,
          actions,
        };
      });

    const formFieldSelectors = new Set(
      forms.flatMap((form) => form.fields.map((field) => field.selector))
    );
    const looseFields = allFields
      .filter((field) => {
        const index = Number(fieldIds.get(field).slice("field-".length));
        return !formFieldSelectors.has(selectorFor(field, `field-${index}`));
      })
      .map((field) => fieldFrom(field, Number(fieldIds.get(field).slice("field-".length))));
    if (looseFields.length > 0) {
      forms.push({
        id: "form-loose",
        text: textOf(document.body.innerText || document.body.textContent, 1000),
        fields: looseFields,
        actions: allActions.map((action, index) => actionFrom(action, index)),
      });
    }

    let origin = "";
    try {
      origin = window.location.origin;
    } catch (_error) {
      origin = "";
    }

    return {
      url: window.location.href,
      origin,
      title: document.title || "",
      forms,
      actions: allActions.map((action, index) => actionFrom(action, index)),
      browser_error: browserError(),
    };
  });

  return { ok: true, value };
}

async function runClient(parsedArgs) {
  if (parsedArgs.action) {
    const payload = JSON.parse(parsedArgs.action);
    const response = await sendRequest({ command: "action", payload });
    ensureOk(response);
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
