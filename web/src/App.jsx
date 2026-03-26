import { useCallback, useEffect, useMemo, useState } from "react";

const initialCase = { name: "" };

function formatDate(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function clampPercent(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(100, num));
}

function App() {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [newCase, setNewCase] = useState(initialCase);
  const [selectedFile, setSelectedFile] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [analyses, setAnalyses] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [report, setReport] = useState(null);
  const [timelineQuery, setTimelineQuery] = useState("");
  const [status, setStatus] = useState({ type: "info", message: "Ready" });
  const [isBusy, setIsBusy] = useState(false);

  const selectedCase = useMemo(
    () => cases.find((entry) => String(entry.id) === String(selectedCaseId)) || null,
    [cases, selectedCaseId],
  );

  const canUpload = Boolean(selectedCaseId && selectedFile);
  const topThreatRows = useMemo(
    () => analyses.slice().sort((a, b) => b.threatScore - a.threatScore).slice(0, 5),
    [analyses],
  );
  const timelineByHour = useMemo(() => {
    const bucket = new Map();
    for (const event of timeline) {
      const date = new Date(event.eventTime);
      if (Number.isNaN(date.getTime())) continue;
      const hourKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(
        date.getDate(),
      ).padStart(2, "0")} ${String(date.getHours()).padStart(2, "0")}:00`;
      bucket.set(hourKey, (bucket.get(hourKey) || 0) + 1);
    }
    return Array.from(bucket.entries())
      .map(([hour, count]) => ({ hour, count }))
      .sort((a, b) => a.hour.localeCompare(b.hour))
      .slice(-10);
  }, [timeline]);
  const timelineMax = useMemo(
    () => Math.max(1, ...timelineByHour.map((item) => item.count)),
    [timelineByHour],
  );

  async function request(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || "Request failed");
    }
    return payload;
  }

  const loadCases = useCallback(async () => {
    const data = await request("/api/cases");
    setCases(data.cases || []);
    if (!selectedCaseId && data.cases?.length) {
      setSelectedCaseId(String(data.cases[0].id));
    }
  }, [selectedCaseId]);

  const loadCaseData = useCallback(async (caseId, search = "") => {
    if (!caseId) {
      setEvidence([]);
      setAnalyses([]);
      setTimeline([]);
      setReport(null);
      return;
    }

    const [evidenceRes, analysisRes, timelineRes, reportRes] = await Promise.all([
      request(`/api/evidence?caseId=${encodeURIComponent(caseId)}`),
      request(`/api/analyses?caseId=${encodeURIComponent(caseId)}`),
      request(
        `/api/timeline?caseId=${encodeURIComponent(caseId)}&q=${encodeURIComponent(search.trim())}`,
      ),
      request(`/api/report/${encodeURIComponent(caseId)}`),
    ]);

    setEvidence(evidenceRes.evidence || []);
    setAnalyses(analysisRes.analyses || []);
    setTimeline(timelineRes.timeline || []);
    setReport(reportRes.report || null);
  }, []);

  useEffect(() => {
    loadCases().catch((error) => setStatus({ type: "error", message: error.message }));
  }, [loadCases]);

  useEffect(() => {
    loadCaseData(selectedCaseId).catch((error) =>
      setStatus({ type: "error", message: error.message }),
    );
  }, [loadCaseData, selectedCaseId]);

  useEffect(() => {
    if (!selectedCaseId) return;
    const timer = setTimeout(() => {
      loadCaseData(selectedCaseId, timelineQuery).catch((error) =>
        setStatus({ type: "error", message: error.message }),
      );
    }, 250);
    return () => clearTimeout(timer);
  }, [loadCaseData, selectedCaseId, timelineQuery]);

  async function handleCreateCase(event) {
    event.preventDefault();
    const name = newCase.name.trim();
    if (!name) {
      setStatus({ type: "error", message: "Case name is required." });
      return;
    }

    setIsBusy(true);
    try {
      const payload = await request("/api/cases", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setCases((prev) => [payload.case, ...prev]);
      setSelectedCaseId(String(payload.case.id));
      setNewCase(initialCase);
      setStatus({ type: "success", message: "Case created successfully." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function handleUpload(event) {
    event.preventDefault();
    if (!canUpload) {
      setStatus({ type: "error", message: "Select a case and file first." });
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("caseId", selectedCaseId);
    setIsBusy(true);
    try {
      const response = await fetch("/api/evidence", { method: "POST", body: formData });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "Upload failed");
      }
      setSelectedFile(null);
      await loadCaseData(selectedCaseId);
      setStatus({ type: "success", message: "Evidence uploaded." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function runAnalysis(evidenceId) {
    setIsBusy(true);
    try {
      await request("/api/analyze", {
        method: "POST",
        body: JSON.stringify({ evidenceId }),
      });
      await loadCaseData(selectedCaseId);
      setStatus({ type: "success", message: "Analysis completed." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function runCaseAnalysis() {
    if (!selectedCaseId) return;
    setIsBusy(true);
    try {
      const payload = await request("/api/analyze-case", {
        method: "POST",
        body: JSON.stringify({ caseId: selectedCaseId }),
      });
      await loadCaseData(selectedCaseId, timelineQuery);
      setStatus({
        type: "success",
        message: `Analyzed ${payload.analyzedEvidenceCount} evidence file(s).`,
      });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function deleteCase() {
    if (!selectedCaseId) return;
    const ok = window.confirm("Delete this case and all associated data?");
    if (!ok) return;
    setIsBusy(true);
    try {
      await request(`/api/cases/${encodeURIComponent(selectedCaseId)}`, { method: "DELETE" });
      setCases((prev) => prev.filter((entry) => String(entry.id) !== String(selectedCaseId)));
      setSelectedCaseId("");
      setEvidence([]);
      setAnalyses([]);
      setTimeline([]);
      setReport(null);
      setStatus({ type: "success", message: "Case deleted." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function deleteEvidence(evidenceId) {
    const ok = window.confirm("Delete this evidence and all related analysis/timeline data?");
    if (!ok) return;
    setIsBusy(true);
    try {
      await request(`/api/evidence/${encodeURIComponent(evidenceId)}`, { method: "DELETE" });
      await loadCaseData(selectedCaseId, timelineQuery);
      setStatus({ type: "success", message: "Evidence deleted." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  function exportReportJson() {
    if (!report) {
      setStatus({ type: "error", message: "No report available to export." });
      return;
    }
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${String(report.caseName || "case").replace(/\s+/g, "_").toLowerCase()}_report.json`;
    link.click();
    URL.revokeObjectURL(url);
    setStatus({ type: "success", message: "Report JSON exported." });
  }

  return (
    <div className="app-shell">
      <header className="header">
        <h1>Cyber Triage Tool</h1>
        <p>Upload evidence, run lightweight triage, and inspect timeline artifacts.</p>
      </header>

      <section className="panel">
        <h2>Case Management</h2>
        <form className="row" onSubmit={handleCreateCase}>
          <input
            value={newCase.name}
            onChange={(event) => setNewCase({ name: event.target.value })}
            placeholder="Enter case name"
            maxLength={120}
            disabled={isBusy}
          />
          <button type="submit" disabled={isBusy}>Create Case</button>
        </form>
        <div className="row">
          <label htmlFor="caseSelect">Active Case</label>
          <select
            id="caseSelect"
            value={selectedCaseId}
            onChange={(event) => setSelectedCaseId(event.target.value)}
            disabled={isBusy || cases.length === 0}
          >
            <option value="">Select case</option>
            {cases.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.name}
              </option>
            ))}
          </select>
          <button type="button" onClick={deleteCase} disabled={!selectedCaseId || isBusy}>
            Delete Case
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>Evidence Upload</h2>
        <form className="row" onSubmit={handleUpload}>
          <input
            type="file"
            onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
            disabled={!selectedCaseId || isBusy}
          />
          <button type="submit" disabled={!canUpload || isBusy}>Upload</button>
        </form>
        <p className="muted">Accepted: .txt, .log, .csv, .json (max 5MB)</p>
      </section>

      <section className="panel">
        <h2>Evidence List</h2>
        <div className="row">
          <button type="button" onClick={runCaseAnalysis} disabled={!selectedCaseId || isBusy || evidence.length === 0}>
            Analyze All Evidence
          </button>
        </div>
        {!selectedCase ? (
          <p className="muted">Select a case to view evidence.</p>
        ) : evidence.length === 0 ? (
          <p className="muted">No evidence uploaded yet.</p>
        ) : (
          evidence.map((item) => (
            <div className="card" key={item.id}>
              <div>
                <strong>{item.filename}</strong>
                <p className="muted">
                  {item.mimeType || "unknown"} | {item.byteSize} bytes | {formatDate(item.createdAt)}
                </p>
              </div>
              <div className="row">
                <button onClick={() => runAnalysis(item.id)} disabled={isBusy}>Run Analysis</button>
                <button onClick={() => deleteEvidence(item.id)} disabled={isBusy}>Delete</button>
              </div>
            </div>
          ))
        )}
      </section>

      <section className="panel">
        <h2>Analysis Results</h2>
        {analyses.length === 0 ? (
          <p className="muted">No analyses available.</p>
        ) : (
          analyses.map((entry) => (
            <div className="card" key={entry.id}>
              <div>
                <strong>{entry.evidenceFilename}</strong>
                <p className="muted">
                  Threat score: {entry.threatScore} | Lines: {entry.lineCount} | IOC hits: {entry.iocCount}
                </p>
              </div>
              <p>{entry.summary}</p>
            </div>
          ))
        )}
      </section>

      <section className="panel">
        <h2>Triage Charts</h2>
        {analyses.length === 0 ? (
          <p className="muted">Run at least one analysis to view chart data.</p>
        ) : (
          <>
            <h3 className="subheading">Threat Score by Evidence (Top 5)</h3>
            <div className="bar-chart">
              {topThreatRows.map((entry) => (
                <div className="bar-row" key={entry.id}>
                  <span className="bar-label">{entry.evidenceFilename}</span>
                  <div className="bar-track">
                    <div
                      className="bar-fill threat"
                      style={{ width: `${clampPercent(entry.threatScore)}%` }}
                    />
                  </div>
                  <span className="bar-value">{entry.threatScore}</span>
                </div>
              ))}
            </div>

            <h3 className="subheading">IOC Hits by Evidence (Top 5)</h3>
            <div className="bar-chart">
              {topThreatRows.map((entry) => {
                const maxIoc = Math.max(1, ...topThreatRows.map((row) => row.iocCount));
                const width = clampPercent((entry.iocCount / maxIoc) * 100);
                return (
                  <div className="bar-row" key={`ioc-${entry.id}`}>
                    <span className="bar-label">{entry.evidenceFilename}</span>
                    <div className="bar-track">
                      <div className="bar-fill ioc" style={{ width: `${width}%` }} />
                    </div>
                    <span className="bar-value">{entry.iocCount}</span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      <section className="panel">
        <h2>Timeline</h2>
        <div className="row">
          <input
            type="text"
            value={timelineQuery}
            onChange={(event) => setTimelineQuery(event.target.value)}
            placeholder="Filter timeline by keyword"
            disabled={!selectedCaseId || isBusy}
          />
        </div>
        {timeline.length === 0 ? (
          <p className="muted">No timestamped events extracted yet.</p>
        ) : (
          timeline.map((event) => (
            <div className="card" key={event.id}>
              <strong>{formatDate(event.eventTime)}</strong>
              <p>{event.description}</p>
            </div>
          ))
        )}
        {timelineByHour.length > 0 && (
          <>
            <h3 className="subheading">Timeline Event Volume (Recent Hours)</h3>
            <div className="sparkline-wrap">
              {timelineByHour.map((item) => {
                const height = Math.round((item.count / timelineMax) * 100);
                return (
                  <div className="spark-bar" key={item.hour} title={`${item.hour} - ${item.count} events`}>
                    <div className="spark-fill" style={{ height: `${height}%` }} />
                  </div>
                );
              })}
            </div>
            <p className="muted">
              Latest: {timelineByHour[timelineByHour.length - 1].hour} (
              {timelineByHour[timelineByHour.length - 1].count} events)
            </p>
          </>
        )}
      </section>

      <section className="panel">
        <h2>Case Report</h2>
        {!report ? (
          <p className="muted">No report available.</p>
        ) : (
          <>
            <div className="card">
              <p><strong>Case:</strong> {report.caseName}</p>
              <p><strong>Evidence:</strong> {report.evidenceCount}</p>
              <p><strong>Analyses:</strong> {report.analysisCount}</p>
              <p><strong>Total IOC Hits:</strong> {report.totalIocHits}</p>
              <p><strong>Average Threat Score:</strong> {report.avgThreatScore}</p>
              <p><strong>Overall Risk:</strong> {report.riskLevel}</p>
            </div>
            <div className="row">
              <button type="button" onClick={exportReportJson} disabled={isBusy}>Export Report JSON</button>
            </div>
          </>
        )}
      </section>

      <footer className={`status ${status.type}`}>{status.message}</footer>
    </div>
  );
}

export default App;
