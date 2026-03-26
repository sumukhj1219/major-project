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

function extractTimelineEvents(content, maxEvents = 100) {
  const lines = content.split(/\r?\n/).slice(0, 5000);
  const events = [];
  const timestampRegex =
    /\b(20\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[ T](?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?)\b/;

  for (const line of lines) {
    const match = line.match(timestampRegex);
    if (!match) continue;
    const date = new Date(match[1].replace("/", "-").replace("/", "-"));
    if (Number.isNaN(date.getTime())) continue;
    events.push({
      eventTime: date.toISOString(),
      description: line.trim().slice(0, 300) || "Timestamped event",
    });
    if (events.length >= maxEvents) break;
  }
  return events;
}

function runAnalysisForEvidence(evidenceRow) {
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

  const risk = riskFromScore(threatScore);
  const summary =
    `Detected ${iocCount} potential indicator(s) across ${lineCount} parsed line(s). ` +
    `Computed risk level is ${risk.toUpperCase()}.`;

  return { lineCount, iocCount, threatScore, summary };
}

function getCaseById(caseId) {
  return db.prepare("SELECT * FROM cases WHERE id = ?").get(caseId);
}

function analyzeEvidenceRecord(evidence) {
  const { lineCount, iocCount, threatScore, summary } = runAnalysisForEvidence(evidence);
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO analyses (caseId, evidenceId, evidenceFilename, lineCount, iocCount, threatScore, summary, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    evidence.caseId,
    evidence.id,
    evidence.filename,
    lineCount,
    iocCount,
    threatScore,
    summary,
    createdAt,
  );

  const events = extractTimelineEvents(evidence.content);
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

  return { analysis, timelineEventsInserted: events.length };
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
    .prepare("SELECT id, caseId, filename, mimeType, byteSize, createdAt FROM evidence WHERE caseId = ? ORDER BY createdAt DESC")
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
  const content = raw.replace(/\0/g, "").slice(0, 2_000_000);
  if (!content.trim()) {
    res.status(400).json({ error: "Uploaded file has no readable content." });
    return;
  }

  const createdAt = new Date().toISOString();
  const insert = db
    .prepare(`
      INSERT INTO evidence (caseId, filename, mimeType, byteSize, content, createdAt)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(
      caseId,
      req.file.originalname.slice(0, 255),
      req.file.mimetype || "application/octet-stream",
      Number(req.file.size || 0),
      content,
      createdAt,
    );

  const row = db
    .prepare("SELECT id, caseId, filename, mimeType, byteSize, createdAt FROM evidence WHERE id = ?")
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

app.post("/api/analyze", (req, res) => {
  const evidenceId = Number(req.body?.evidenceId);
  if (!Number.isInteger(evidenceId) || evidenceId <= 0) {
    res.status(400).json({ error: "Valid evidenceId is required." });
    return;
  }

  const evidence = db.prepare("SELECT * FROM evidence WHERE id = ?").get(evidenceId);
  if (!evidence) {
    res.status(404).json({ error: "Evidence not found." });
    return;
  }

  const result = analyzeEvidenceRecord(evidence);
  res.status(201).json(result);
});

app.post("/api/analyze-case", (req, res) => {
  const caseId = Number(req.body?.caseId);
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
    const result = analyzeEvidenceRecord(evidence);
    timelineEventsInserted += result.timelineEventsInserted;
  }

  res.status(201).json({
    analyzedEvidenceCount: evidenceRows.length,
    timelineEventsInserted,
  });
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
    .all(caseId);
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
