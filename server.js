// server.js
import { createServer as createHttpsServer } from "https";
import { createServer as createHttpServer } from "http";
import next from "next";
import fs from "fs";
import path from "path";
import os from "os";
import { exec } from "child_process";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ────────────────────────────────────────────────────────────────
// CONFIGURATION
// ────────────────────────────────────────────────────────────────
const config = {
  dev: process.env.NODE_ENV !== "production",
  hostname: "0.0.0.0",
  port: parseInt(process.env.PORT || "443", 10),
  httpPort: parseInt(process.env.HTTP_PORT || "80", 10),
  enableHttpRedirect: true,
  enableRequestLogging: true,
  enableCompression: false,
  turbopack: true,
  autoOpenBrowser: true,
  preferredBrowser: null,
};

// ────────────────────────────────────────────────────────────────
// UTILS
// ────────────────────────────────────────────────────────────────
const colors = {
  reset: "\x1b[0m", bright: "\x1b[1m", dim: "\x1b[2m",
  green: "\x1b[32m", yellow: "\x1b[33m", blue: "\x1b[34m",
  magenta: "\x1b[35m", cyan: "\x1b[36m", red: "\x1b[31m", gray: "\x1b[90m"
};

const c = (color, text) => `${colors[color]}${text}${colors.reset}`;

function getLocalIPs() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) addresses.push({ name, address: iface.address });
    }
  }
  return addresses;
}

function getSystemInfo() {
  const cpus = os.cpus();
  return {
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,
    cpuModel: cpus[0]?.model || "Unknown",
    cpuCores: cpus.length,
    totalMemory: (os.totalmem() / 1024 / 1024 / 1024).toFixed(2) + " GB",
    freeMemory: (os.freemem() / 1024 / 1024 / 1024).toFixed(2) + " GB",
    uptime: formatUptime(os.uptime()),
  };
}

function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  return parts.join(" ") || "<1m";
}

function getTimestamp() {
  return new Date().toISOString().replace("T", " ").substring(0, 19);
}

function checkCertificates() {
  const keyPath = path.join(__dirname, "certs", "localhost.key");
  const certPath = path.join(__dirname, "certs", "localhost.crt");
  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.error(c("red", "❌ SSL certificates not found!"));
    process.exit(1);
  }
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

// ────────────────────────────────────────────────────────────────
// REQUEST LOGGER
// ────────────────────────────────────────────────────────────────
function logRequest(req, res, duration) {
  if (!config.enableRequestLogging) return;
  const url = req.url || "";
  if (url.includes("/_next/") || url.includes("/favicon.ico")) return;
  const method = req.method || "GET";
  const status = res.statusCode;
  const statusColor = status >= 400 ? "red" : status >= 300 ? "yellow" : "green";
  const methodColor = { GET: "cyan", POST: "green", PUT: "yellow", DELETE: "red", PATCH: "magenta" }[method] || "gray";
  console.log(`${c("gray", getTimestamp())} ${c(methodColor, method.padEnd(6))} ${c(statusColor, status)} ${c("dim", `${duration}ms`.padStart(6))} ${url}`);
}

// ────────────────────────────────────────────────────────────────
// MAIN SERVER
// ────────────────────────────────────────────────────────────────
async function startServer() {
  const httpsOptions = checkCertificates();
  const localIPs = getLocalIPs();
  const app = next({ dev: config.dev, hostname: config.hostname, port: config.port, turbopack: config.turbopack });
  const handle = app.getRequestHandler();
  await app.prepare();

  const httpsServer = createHttpsServer(httpsOptions, async (req, res) => {
    const start = Date.now();
    res.on("finish", () => logRequest(req, res, Date.now() - start));
    try {
      const url = new URL(req.url, `https://${req.headers.host}`);
      await handle(req, res, url);
    } catch (err) {
      console.error(c("red", "Server error:"), err);
      res.statusCode = 500;
      res.end("Internal server error");
    }
  });

  httpsServer.listen(config.port, config.hostname, () => {
    console.log(c("green", `✅ HTTPS server running on port ${config.port}`));
  });

  let httpServer = null;
  if (config.enableHttpRedirect) {
    httpServer = createHttpServer((req, res) => {
      const host = req.headers.host?.split(":")[0] || "localhost";
      const httpsPort = config.port === 443 ? "" : `:${config.port}`;
      res.writeHead(301, { Location: `https://${host}${httpsPort}${req.url}` });
      res.end();
    });
    httpServer.listen(config.httpPort, config.hostname);
  }
}

startServer().catch((err) => {
  console.error(c("red", "❌ Failed to start server:"), err);
  process.exit(1);
});