import express from "express";
import cors from "cors";
import multer from "multer";
import { DatabaseSync } from "node:sqlite";

const app = express();
const port = Number(process.env.PORT || 5000);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const db = new DatabaseSync(":memory:");
db.exec("PRAGMA journal_mode = WAL;");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = [".txt", ".log", ".csv", ".json"];
    const lower = String(file.originalname || "").toLowerCase();
    const isAllowed = allowedExtensions.some((ext) => lower.endsWith(ext));
    if (!isAllowed) {
      cb(new Error("Unsupported file type. Allowed: .txt, .log, .csv, .json"));
      return;
    }
    cb(null, true);
  },
});

function initDb() {
  db.exec(`
    CREATE TABLE cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      createdAt TEXT NOT NULL
    );

    CREATE TABLE evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caseId INTEGER NOT NULL,
      filename TEXT NOT NULL,
      mimeType TEXT,
      logFormat TEXT NOT NULL,
      providerHint TEXT NOT NULL,
      byteSize INTEGER NOT NULL,
      content TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      FOREIGN KEY(caseId) REFERENCES cases(id)
    );

    CREATE TABLE analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caseId INTEGER NOT NULL,
      evidenceId INTEGER NOT NULL,
      evidenceFilename TEXT NOT NULL,
      lineCount INTEGER NOT NULL,
      iocCount INTEGER NOT NULL,
      threatScore INTEGER NOT NULL,
      summary TEXT NOT NULL,
      playwrightFindings TEXT NOT NULL DEFAULT '[]',
      createdAt TEXT NOT NULL,
      FOREIGN KEY(caseId) REFERENCES cases(id),
      FOREIGN KEY(evidenceId) REFERENCES evidence(id)
    );

    CREATE TABLE timeline (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caseId INTEGER NOT NULL,
      evidenceId INTEGER NOT NULL,
      eventTime TEXT NOT NULL,
      description TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      FOREIGN KEY(caseId) REFERENCES cases(id),
      FOREIGN KEY(evidenceId) REFERENCES evidence(id)
    );
  `);
}

function sanitizeCaseName(input) {
  return String(input || "").trim().replace(/\s+/g, " ").slice(0, 120);
}

function riskFromScore(score) {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

const timestampRegexes = [
  /\b20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/,
  /\b20\d{2}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}:\d{2}\b/,
  /\b20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}\b/,
];

const providerRules = [
  { provider: "supabase", regex: /\bsupabase\b|\bpostgrest\b|\bgotrue\b|\brealtime\b/i },
  { provider: "neon", regex: /\bneon\b|\bneondb\b/i },
  { provider: "postgres", regex: /\bpostgres(?:ql)?\b|\bpg_\w+\b/i },
  { provider: "mysql", regex: /\bmysql\b|\bmariadb\b/i },
  { provider: "cloudflare", regex: /\bcloudflare\b|\bcf-ray\b/i },
  { provider: "aws", regex: /\baws\b|\bcloudwatch\b|\blambda\b/i },
  { provider: "gcp", regex: /\bgcp\b|\bstackdriver\b|\bgoogle cloud\b/i },
];

function parseTimestamp(value) {
  if (!value) return null;
  const text = String(value).trim();
  if (!text) return null;
  const parsed = new Date(text);
  if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  for (const regex of timestampRegexes) {
    const match = text.match(regex);
    if (!match) continue;
    const date = new Date(match[0].replace(/\//g, "-"));
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  return null;
}

function detectProvider(text, filename = "") {
  const input = `${filename}\n${text || ""}`;
  for (const rule of providerRules) {
    if (rule.regex.test(input)) return rule.provider;
  }
  return "generic";
}

function normalizeSeverity(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "info";
  if (/\b(trace|debug)\b/.test(normalized)) return "debug";
  if (/\b(info|notice|log)\b/.test(normalized)) return "info";
  if (/\b(warn|warning)\b/.test(normalized)) return "warning";
  if (/\b(error|err|fatal|critical|panic)\b/.test(normalized)) return "error";
  return "info";
}

function toEventFromObject(value, fallbackProvider) {
  const timestamp = parseTimestamp(
    value.timestamp || value.time || value.ts || value.logged_at || value.created_at || value.date,
  );
  const severity = normalizeSeverity(value.level || value.severity || value.log_level || value.priority);
  const message =
    String(
      value.message ||
        value.msg ||
        value.error ||
        value.event ||
        value.description ||
        value.details ||
        JSON.stringify(value),
    ).slice(0, 1000) || "log event";
  const provider = detectProvider(message, value.source || fallbackProvider);
  return { timestamp, severity, provider, message };
}

function parseCsvToObjects(content) {
  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((cell) => cell.trim().replace(/^"|"$/g, ""));
  return lines.slice(1, 2000).map((line) => {
    const cells = line.split(",").map((cell) => cell.trim().replace(/^"|"$/g, ""));
    const row = {};
    for (let idx = 0; idx < headers.length; idx += 1) {
      row[headers[idx] || `col_${idx}`] = cells[idx] || "";
    }
    return row;
  });
}

function normalizeLogContent(content, filename = "", mimeType = "") {
  const raw = String(content || "");
  const trimmed = raw.trim();
  const initialProvider = detectProvider(trimmed.slice(0, 5000), filename);
  const normalizedEvents = [];
  let format = "text";

  if ((mimeType || "").includes("json") || /\.(json|ndjson)$/i.test(filename)) {
    format = "json";
    const rows = [];
    for (const line of trimmed.split(/\r?\n/).slice(0, 2000)) {
      const candidate = line.trim();
      if (!candidate) continue;
      try {
        rows.push(JSON.parse(candidate));
      } catch {
        if (rows.length === 0) {
          try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed)) rows.push(...parsed.slice(0, 2000));
            else rows.push(parsed);
          } catch {
            format = "text";
          }
        }
      }
    }
    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      normalizedEvents.push(toEventFromObject(row, initialProvider));
    }
  } else if ((mimeType || "").includes("csv") || /\.csv$/i.test(filename)) {
    format = "csv";
    const rows = parseCsvToObjects(raw);
    for (const row of rows) {
      normalizedEvents.push(toEventFromObject(row, initialProvider));
    }
  }

  if (normalizedEvents.length === 0) {
    format = "text";
    const lines = raw.split(/\r?\n/).slice(0, 5000);
    for (const line of lines) {
      const text = line.trim();
      if (!text) continue;
      normalizedEvents.push({
        timestamp: parseTimestamp(text),
        severity: normalizeSeverity(text),
        provider: detectProvider(text, filename),
        message: text.slice(0, 1000),
      });
    }
  }

  const providerCounts = {};
  for (const event of normalizedEvents) {
    providerCounts[event.provider] = (providerCounts[event.provider] || 0) + 1;
  }
  const providerHint =
    Object.entries(providerCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || initialProvider || "generic";

  const normalizedContent = normalizedEvents
    .slice(0, 8000)
    .map((event) => {
      const ts = event.timestamp || "no-timestamp";
      return `${ts} [${event.provider}] [${event.severity}] ${event.message}`;
    })
    .join("\n");

  return {
    format,
    providerHint,
    events: normalizedEvents,
    normalizedContent: normalizedContent || raw.slice(0, 2_000_000),
  };
}

function extractTimelineEvents(events, maxEvents = 100) {
  const timeline = [];
  for (const event of events) {
    if (!event.timestamp) continue;
    timeline.push({
      eventTime: event.timestamp,
      description: `[${event.provider}] [${event.severity}] ${event.message}`.slice(0, 300),
    });
    if (timeline.length >= maxEvents) break;
  }
  return timeline;
}

async function inspectUrlsWithPlaywright(urls = [], maxUrls = 3) {
  const cleanUrls = Array.from(
    new Set(
      urls
        .map((url) => String(url || "").trim().replace(/[),.;]+$/, ""))
        .filter((url) => /^https?:\/\/[^\s"'<>]+$/i.test(url)),
    ),
  ).slice(0, Math.max(1, Math.min(maxUrls, 10)));
  if (cleanUrls.length === 0) return [];

  let chromium = null;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    return [];
  }
  if (!chromium) return [];

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const findings = [];

  try {
    for (const url of cleanUrls) {
      try {
        const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 7000 });
        const title = (await page.title()).slice(0, 200);
        const finalUrl = page.url();
        const finalParsed = new URL(finalUrl);
        const status = response?.status?.() ?? null;
        const contentType = response?.headers?.()["content-type"] || "";
        const snippet = await page
          .evaluate(() => document.body?.innerText?.replace(/\s+/g, " ").trim().slice(0, 220) || "")
          .catch(() => "");
        const lowerSignals = `${title} ${finalUrl} ${snippet}`.toLowerCase();
        const looksAuthWall =
          /\blog ?in\b|\bsign ?in\b|\bauth\b|\boauth\b|\bcontinue with\b|\baccess denied\b/.test(lowerSignals);
        findings.push({
          url,
          finalUrl,
          status,
          title: title || "untitled",
          contentType: contentType.slice(0, 120),
          hostname: finalParsed.hostname,
          path: finalParsed.pathname,
          usesHttps: finalParsed.protocol === "https:",
          redirected: String(url).replace(/\/+$/, "") !== String(finalUrl).replace(/\/+$/, ""),
          reachable: status !== null,
          looksAuthWall,
          snippet,
          inspectedAt: new Date().toISOString(),
        });
      } catch (error) {
        findings.push({
          url,
          finalUrl: null,
          status: null,
          title: "unreachable",
          contentType: "",
          hostname: "",
          path: "",
          usesHttps: /^https:\/\//i.test(url),
          redirected: false,
          reachable: false,
          looksAuthWall: false,
          snippet: "",
          error: String(error?.message || "navigation failed").slice(0, 180),
          inspectedAt: new Date().toISOString(),
        });
      }
    }
  } finally {
    await page.close();
    await browser.close();
  }

  return findings;
}

function normalizeUrlInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  return withProtocol.replace(/\s+/g, "");
}

async function enrichSuspiciousUrlsWithPlaywright(content, maxUrls = 3) {
  const urlMatches = Array.from(
    new Set(
      (content.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || [])
        .map((url) => url.replace(/[),.;]+$/, ""))
        .slice(0, 20),
    ),
  );
  return inspectUrlsWithPlaywright(urlMatches, maxUrls);
}

async function runAnalysisForEvidence(evidenceRow, options = {}) {
  const content = evidenceRow.content || "";
  const lines = content.split(/\r?\n/).filter(Boolean);
  const lineCount = lines.length;
  const iocPatterns = [
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, // IPv4-like
    /\b(?:cmd\.exe|powershell|mimikatz|rundll32|regsvr32|wmic)\b/gi,
    /\b(?:malware|ransomware|backdoor|persistence|exfiltration|c2)\b/gi,
    /\b(?:failed login|privilege escalation|unauthorized|suspicious)\b/gi,
    /\b[a-f0-9]{32,64}\b/gi, // hash-like
  ];

  let iocCount = 0;
  const inspected = content.slice(0, 300000);
  for (const pattern of iocPatterns) {
    const found = inspected.match(pattern);
    iocCount += found ? found.length : 0;
  }

  const density = lineCount > 0 ? iocCount / lineCount : iocCount;
  let threatScore = Math.min(100, Math.round(iocCount * 3 + density * 40));
  if (!Number.isFinite(threatScore) || threatScore < 0) {
    threatScore = 0;
  }
  const playwrightFindings = options.enrichWithPlaywright
    ? await enrichSuspiciousUrlsWithPlaywright(content)
    : [];
  threatScore = Math.min(100, threatScore + playwrightFindings.length * 5);

  const risk = riskFromScore(threatScore);
  const summary =
    `Detected ${iocCount} potential indicator(s) across ${lineCount} parsed line(s). ` +
    `${playwrightFindings.length > 0 ? `Playwright inspected ${playwrightFindings.length} suspicious URL(s). ` : ""}` +
    `Computed risk level is ${risk.toUpperCase()}.`;

  return { lineCount, iocCount, threatScore, summary, playwrightFindings };
}

function getCaseById(caseId) {
  return db.prepare("SELECT * FROM cases WHERE id = ?").get(caseId);
}

function buildAnalystBrief(stats, caseName) {
  const evidenceCount = Number(stats.evidenceCount || 0);
  const analysisCount = Number(stats.analysisCount || 0);
  const totalIocHits = Number(stats.totalIocHits || 0);
  const avgThreatScore = Number(stats.avgThreatScore || 0);
  const riskLevel = riskFromScore(avgThreatScore).toUpperCase();
  return `${caseName}: ${evidenceCount} evidence file(s), ${analysisCount} completed analysis run(s), ${totalIocHits} IOC hit(s), average threat score ${avgThreatScore} (${riskLevel}).`;
}

async function analyzeEvidenceRecord(evidence, options = {}) {
  const { lineCount, iocCount, threatScore, summary, playwrightFindings } =
    await runAnalysisForEvidence(evidence, options);
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO analyses (caseId, evidenceId, evidenceFilename, lineCount, iocCount, threatScore, summary, playwrightFindings, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    evidence.caseId,
    evidence.id,
    evidence.filename,
    lineCount,
    iocCount,
    threatScore,
    summary,
    JSON.stringify(playwrightFindings || []),
    createdAt,
  );

  const { events: normalizedEvents } = normalizeLogContent(
    evidence.content,
    evidence.filename,
    evidence.mimeType,
  );
  const events = extractTimelineEvents(normalizedEvents);
  if (events.length > 0) {
    const insertEvent = db.prepare(`
      INSERT INTO timeline (caseId, evidenceId, eventTime, description, createdAt)
      VALUES (?, ?, ?, ?, ?)
    `);
    db.exec("BEGIN");
    try {
      for (const event of events) {
        insertEvent.run(evidence.caseId, evidence.id, event.eventTime, event.description, createdAt);
      }
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  const analysis = db
    .prepare("SELECT * FROM analyses WHERE evidenceId = ? ORDER BY createdAt DESC LIMIT 1")
    .get(evidence.id);

  return { analysis: { ...analysis, playwrightFindings }, timelineEventsInserted: events.length };
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, db: "in-memory sqlite", timestamp: new Date().toISOString() });
});

app.get("/api/cases", (_req, res) => {
  const rows = db.prepare("SELECT * FROM cases ORDER BY createdAt DESC").all();
  res.json({ cases: rows });
});

app.post("/api/cases", (req, res) => {
  const name = sanitizeCaseName(req.body?.name);
  if (!name) {
    res.status(400).json({ error: "Case name is required." });
    return;
  }

  try {
    const createdAt = new Date().toISOString();
    const result = db
      .prepare("INSERT INTO cases (name, createdAt) VALUES (?, ?)")
      .run(name, createdAt);
    const row = db.prepare("SELECT * FROM cases WHERE id = ?").get(result.lastInsertRowid);
    res.status(201).json({ case: row });
  } catch (error) {
    if (String(error.message || "").includes("UNIQUE")) {
      res.status(409).json({ error: "Case name already exists." });
      return;
    }
    res.status(500).json({ error: "Failed to create case." });
  }
});

app.delete("/api/cases/:caseId", (req, res) => {
  const caseId = Number(req.params.caseId);
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId path parameter is required." });
    return;
  }
  const caseRow = getCaseById(caseId);
  if (!caseRow) {
    res.status(404).json({ error: "Case not found." });
    return;
  }

  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM timeline WHERE caseId = ?").run(caseId);
    db.prepare("DELETE FROM analyses WHERE caseId = ?").run(caseId);
    db.prepare("DELETE FROM evidence WHERE caseId = ?").run(caseId);
    db.prepare("DELETE FROM cases WHERE id = ?").run(caseId);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }

  res.json({ deleted: true, caseId });
});

app.get("/api/evidence", (req, res) => {
  const caseId = Number(req.query.caseId);
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId query parameter is required." });
    return;
  }
  if (!getCaseById(caseId)) {
    res.status(404).json({ error: "Case not found." });
    return;
  }

  const rows = db
    .prepare(`
      SELECT
        id,
        caseId,
        filename,
        mimeType,
        logFormat,
        providerHint,
        byteSize,
        createdAt,
        substr(content, 1, 650) AS previewLog
      FROM evidence
      WHERE caseId = ?
      ORDER BY createdAt DESC
    `)
    .all(caseId);
  res.json({ evidence: rows });
});

app.post("/api/evidence", (req, res, next) => {
  upload.single("file")(req, res, (error) => {
    if (error) {
      res.status(400).json({ error: error.message || "Upload failed." });
      return;
    }
    next();
  });
}, (req, res) => {
  const caseId = Number(req.body?.caseId);
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId is required." });
    return;
  }
  if (!getCaseById(caseId)) {
    res.status(404).json({ error: "Case not found." });
    return;
  }
  if (!req.file?.buffer) {
    res.status(400).json({ error: "File is required." });
    return;
  }

  const raw = req.file.buffer.toString("utf8");
  const cleanRaw = raw.replace(/\0/g, "").slice(0, 2_000_000);
  const normalized = normalizeLogContent(cleanRaw, req.file.originalname, req.file.mimetype);
  const content = normalized.normalizedContent;
  if (!content.trim()) {
    res.status(400).json({ error: "Uploaded file has no readable content." });
    return;
  }

  const createdAt = new Date().toISOString();
  const insert = db
    .prepare(`
      INSERT INTO evidence (caseId, filename, mimeType, logFormat, providerHint, byteSize, content, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      caseId,
      req.file.originalname.slice(0, 255),
      req.file.mimetype || "application/octet-stream",
      normalized.format,
      normalized.providerHint,
      Number(req.file.size || 0),
      content,
      createdAt,
    );

  const row = db
    .prepare("SELECT id, caseId, filename, mimeType, logFormat, providerHint, byteSize, createdAt FROM evidence WHERE id = ?")
    .get(insert.lastInsertRowid);

  res.status(201).json({ evidence: row });
});

app.delete("/api/evidence/:evidenceId", (req, res) => {
  const evidenceId = Number(req.params.evidenceId);
  if (!Number.isInteger(evidenceId) || evidenceId <= 0) {
    res.status(400).json({ error: "Valid evidenceId path parameter is required." });
    return;
  }
  const evidence = db.prepare("SELECT * FROM evidence WHERE id = ?").get(evidenceId);
  if (!evidence) {
    res.status(404).json({ error: "Evidence not found." });
    return;
  }

  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM timeline WHERE evidenceId = ?").run(evidenceId);
    db.prepare("DELETE FROM analyses WHERE evidenceId = ?").run(evidenceId);
    db.prepare("DELETE FROM evidence WHERE id = ?").run(evidenceId);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }

  res.json({ deleted: true, evidenceId });
});

app.post("/api/analyze", async (req, res, next) => {
  try {
    const evidenceId = Number(req.body?.evidenceId);
    const enrichWithPlaywright = Boolean(req.body?.enrichWithPlaywright);
    if (!Number.isInteger(evidenceId) || evidenceId <= 0) {
      res.status(400).json({ error: "Valid evidenceId is required." });
      return;
    }

    const evidence = db.prepare("SELECT * FROM evidence WHERE id = ?").get(evidenceId);
    if (!evidence) {
      res.status(404).json({ error: "Evidence not found." });
      return;
    }

    const result = await analyzeEvidenceRecord(evidence, { enrichWithPlaywright });
    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
});

app.post("/api/analyze-case", async (req, res, next) => {
  try {
    const caseId = Number(req.body?.caseId);
    const enrichWithPlaywright = Boolean(req.body?.enrichWithPlaywright);
    if (!Number.isInteger(caseId) || caseId <= 0) {
      res.status(400).json({ error: "Valid caseId is required." });
      return;
    }
    if (!getCaseById(caseId)) {
      res.status(404).json({ error: "Case not found." });
      return;
    }

    const evidenceRows = db.prepare("SELECT * FROM evidence WHERE caseId = ?").all(caseId);
    if (evidenceRows.length === 0) {
      res.status(400).json({ error: "No evidence available for this case." });
      return;
    }

    let timelineEventsInserted = 0;
    for (const evidence of evidenceRows) {
      const result = await analyzeEvidenceRecord(evidence, { enrichWithPlaywright });
      timelineEventsInserted += result.timelineEventsInserted;
    }

    res.status(201).json({
      analyzedEvidenceCount: evidenceRows.length,
      timelineEventsInserted,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/enrich-url", async (req, res, next) => {
  try {
    const url = normalizeUrlInput(req.body?.url);
    if (!/^https?:\/\/[^\s"'<>]+$/i.test(url)) {
      res.status(400).json({ error: "A valid http/https URL is required." });
      return;
    }
    const findings = await inspectUrlsWithPlaywright([url], 1);
    if (findings.length === 0) {
      res.status(503).json({ error: "Playwright enrichment unavailable on this server." });
      return;
    }
    res.status(201).json({ finding: findings[0], inspectedAt: new Date().toISOString() });
  } catch (error) {
    next(error);
  }
});

app.get("/api/analyses", (req, res) => {
  const caseId = Number(req.query.caseId);
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId query parameter is required." });
    return;
  }
  if (!getCaseById(caseId)) {
    res.status(404).json({ error: "Case not found." });
    return;
  }
  const rows = db
    .prepare("SELECT * FROM analyses WHERE caseId = ? ORDER BY createdAt DESC")
    .all(caseId)
    .map((row) => {
      let findings = [];
      try {
        findings = JSON.parse(row.playwrightFindings || "[]");
      } catch {
        findings = [];
      }
      return { ...row, playwrightFindings: Array.isArray(findings) ? findings : [] };
    });
  res.json({ analyses: rows });
});

app.get("/api/timeline", (req, res) => {
  const caseId = Number(req.query.caseId);
  const query = String(req.query.q || "").trim().toLowerCase();
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId query parameter is required." });
    return;
  }
  if (!getCaseById(caseId)) {
    res.status(404).json({ error: "Case not found." });
    return;
  }
  const rows = query
    ? db
        .prepare("SELECT * FROM timeline WHERE caseId = ? AND LOWER(description) LIKE ? ORDER BY eventTime ASC")
        .all(caseId, `%${query}%`)
    : db
        .prepare("SELECT * FROM timeline WHERE caseId = ? ORDER BY eventTime ASC")
        .all(caseId);
  res.json({ timeline: rows });
});

app.get("/api/report/:caseId", (req, res) => {
  const caseId = Number(req.params.caseId);
  if (!Number.isInteger(caseId) || caseId <= 0) {
    res.status(400).json({ error: "Valid caseId path parameter is required." });
    return;
  }

  const caseRow = getCaseById(caseId);
  if (!caseRow) {
    res.status(404).json({ error: "Case not found." });
    return;
  }

  const stats = db
    .prepare(`
      SELECT
        (SELECT COUNT(*) FROM evidence WHERE caseId = ?) AS evidenceCount,
        (SELECT COUNT(*) FROM analyses WHERE caseId = ?) AS analysisCount,
        (SELECT COALESCE(SUM(iocCount), 0) FROM analyses WHERE caseId = ?) AS totalIocHits,
        (SELECT COALESCE(ROUND(AVG(threatScore), 2), 0) FROM analyses WHERE caseId = ?) AS avgThreatScore
    `)
    .get(caseId, caseId, caseId, caseId);

  const report = {
    caseId,
    caseName: caseRow.name,
    generatedAt: new Date().toISOString(),
    ...stats,
    riskLevel: riskFromScore(Number(stats.avgThreatScore || 0)),
    analystBrief: buildAnalystBrief(stats, caseRow.name),
    topFindings: db
      .prepare(`
        SELECT
          evidenceFilename,
          threatScore,
          iocCount,
          summary,
          createdAt
        FROM analyses
        WHERE caseId = ?
        ORDER BY threatScore DESC, iocCount DESC, createdAt DESC
        LIMIT 5
      `)
      .all(caseId),
    recommendations: [
      "Prioritize investigation of high-scoring evidence first.",
      "Validate IOC hits against known-good baselines before containment.",
      "Correlate suspicious timeline events with identity and network logs.",
    ],
  };

  res.json({ report });
});

app.use((err, _req, res, next) => {
  void next;
  res.status(500).json({ error: err?.message || "Unexpected server error." });
});

initDb();
app.listen(port, () => {
  console.log(`CyberTriage API listening on http://localhost:${port}`);
});
