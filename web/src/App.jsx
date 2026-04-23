import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileBarChart2, FolderSearch, ShieldAlert, UploadCloud } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Checkbox } from "./components/ui/checkbox";
import { Input } from "./components/ui/input";
import { Select } from "./components/ui/select";

const initialCase = { name: "" };

function formatDate(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function summaryVariant(risk) {
  if (risk === "critical" || risk === "high") return "destructive";
  if (risk === "medium") return "warning";
  return "success";
}

function riskFromScore(score) {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function normalizeUrlInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
}

function urlVerdict(finding) {
  if (!finding?.reachable) return { label: "unreachable", tone: "destructive" };
  if (finding.looksAuthWall) return { label: "auth-gated", tone: "warning" };
  if (Number(finding.status || 0) >= 400) return { label: "error-response", tone: "warning" };
  return { label: "reachable", tone: "success" };
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
  const [enrichWithPlaywright, setEnrichWithPlaywright] = useState(false);
  const [manualUrl, setManualUrl] = useState("");
  const [urlFindings, setUrlFindings] = useState([]);
  const [status, setStatus] = useState({ type: "info", message: "Ready" });
  const [isBusy, setIsBusy] = useState(false);

  const canUpload = Boolean(selectedCaseId && selectedFile);
  const topThreatRows = useMemo(
    () =>
      analyses
        .slice()
        .sort((a, b) => b.threatScore - a.threatScore)
        .slice(0, 8)
        .map((entry) => ({
          name: String(entry.evidenceFilename || "").slice(0, 20),
          threatScore: entry.threatScore,
          iocCount: entry.iocCount,
        })),
    [analyses],
  );
  const evidenceById = useMemo(() => {
    const map = new Map();
    for (const row of evidence) {
      map.set(Number(row.id), row);
    }
    return map;
  }, [evidence]);
  const timelineByHour = useMemo(() => {
    const bucket = new Map();
    for (const event of timeline) {
      const date = new Date(event.eventTime);
      if (Number.isNaN(date.getTime())) continue;
      const hourKey = `${String(date.getHours()).padStart(2, "0")}:00`;
      bucket.set(hourKey, (bucket.get(hourKey) || 0) + 1);
    }
    return Array.from(bucket.entries()).map(([hour, events]) => ({ hour, events }));
  }, [timeline]);
  const providerDist = useMemo(() => {
    const map = new Map();
    for (const row of evidence) {
      const provider = row.providerHint || "generic";
      map.set(provider, (map.get(provider) || 0) + 1);
    }
    return Array.from(map.entries()).map(([provider, files]) => ({ provider, files }));
  }, [evidence]);
  const riskDistribution = useMemo(() => {
    const levels = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const item of analyses) {
      const level = riskFromScore(Number(item.threatScore || 0));
      levels[level] += 1;
    }
    return Object.entries(levels).map(([risk, count]) => ({ risk, count }));
  }, [analyses]);
  const scoreTrend = useMemo(() => {
    return analyses
      .slice()
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
      .map((entry) => ({
        at: formatDate(entry.createdAt),
        threatScore: Number(entry.threatScore || 0),
        iocCount: Number(entry.iocCount || 0),
      }))
      .slice(-12);
  }, [analyses]);

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
      request(`/api/timeline?caseId=${encodeURIComponent(caseId)}&q=${encodeURIComponent(search.trim())}`),
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
    loadCaseData(selectedCaseId).catch((error) => setStatus({ type: "error", message: error.message }));
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
    if (!name) return setStatus({ type: "error", message: "Case name is required." });
    setIsBusy(true);
    try {
      const payload = await request("/api/cases", { method: "POST", body: JSON.stringify({ name }) });
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
    if (!canUpload) return setStatus({ type: "error", message: "Select case and file first." });
    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("caseId", selectedCaseId);
    setIsBusy(true);
    try {
      const response = await fetch("/api/evidence", { method: "POST", body: formData });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || "Upload failed");
      setSelectedFile(null);
      await loadCaseData(selectedCaseId);
      setStatus({ type: "success", message: "Evidence uploaded and normalized." });
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
        body: JSON.stringify({ evidenceId, enrichWithPlaywright }),
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
        body: JSON.stringify({ caseId: selectedCaseId, enrichWithPlaywright }),
      });
      await loadCaseData(selectedCaseId, timelineQuery);
      setStatus({ type: "success", message: `Analyzed ${payload.analyzedEvidenceCount} files.` });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function enrichManualUrl() {
    const value = normalizeUrlInput(manualUrl);
    if (!value) {
      setStatus({ type: "error", message: "Enter a URL to enrich." });
      return;
    }
    setIsBusy(true);
    try {
      const payload = await request("/api/enrich-url", {
        method: "POST",
        body: JSON.stringify({ url: value }),
      });
      setManualUrl(value);
      setUrlFindings((prev) => [payload.finding, ...prev].slice(0, 8));
      setStatus({ type: "success", message: "URL enrichment completed." });
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    } finally {
      setIsBusy(false);
    }
  }

  async function deleteCase() {
    if (!selectedCaseId) return;
    if (!window.confirm("Delete this case and all associated data?")) return;
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
    if (!window.confirm("Delete this evidence and related analysis data?")) return;
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
    if (!report) return setStatus({ type: "error", message: "No report to export." });
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${String(report.caseName || "case").replace(/\s+/g, "_").toLowerCase()}_report.json`;
    link.click();
    URL.revokeObjectURL(url);
    setStatus({ type: "success", message: "Report exported." });
  }

  return (
    <main className="mx-auto max-w-7xl space-y-5 p-4 md:p-6">
      <Card className="bg-slate-900 text-white">
        <CardHeader>
          <CardTitle className="text-2xl">Cyber Triage Dashboard</CardTitle>
          <CardDescription className="text-slate-300">
            Cleaner case triage for Supabase, Neon, and mixed log sources.
          </CardDescription>
        </CardHeader>
      </Card>

      <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card><CardHeader><CardDescription>Case</CardDescription><CardTitle>{report?.caseName || "No case"}</CardTitle></CardHeader></Card>
        <Card><CardHeader><CardDescription>Evidence Files</CardDescription><CardTitle>{report?.evidenceCount ?? 0}</CardTitle></CardHeader></Card>
        <Card><CardHeader><CardDescription>Total IOC Hits</CardDescription><CardTitle>{report?.totalIocHits ?? 0}</CardTitle></CardHeader></Card>
        <Card><CardHeader><CardDescription>Overall Risk</CardDescription><CardTitle className="uppercase">{report?.riskLevel || "low"}</CardTitle></CardHeader></Card>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Executive Brief</CardTitle>
          <CardDescription>Short, analyst-ready case snapshot.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-700">{report?.analystBrief || "Run analysis to generate an executive brief."}</p>
          {Array.isArray(report?.recommendations) && report.recommendations.length > 0 && (
            <div className="space-y-1">
              {report.recommendations.map((item) => (
                <p key={item} className="text-xs text-slate-600">- {item}</p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <section className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FolderSearch className="h-4 w-4" /> Case Management</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <form className="flex flex-wrap gap-2" onSubmit={handleCreateCase}>
              <Input value={newCase.name} onChange={(event) => setNewCase({ name: event.target.value })} placeholder="Enter case name" disabled={isBusy} />
              <Button type="submit" disabled={isBusy}>Create Case</Button>
            </form>
            <div className="flex flex-wrap gap-2">
              <Select value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)} disabled={isBusy || cases.length === 0}>
                <option value="">Select case</option>
                {cases.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}
              </Select>
              <Button variant="destructive" onClick={deleteCase} disabled={!selectedCaseId || isBusy}>Delete Case</Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><UploadCloud className="h-4 w-4" /> Upload</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <form className="space-y-2" onSubmit={handleUpload}>
              <Input type="file" onChange={(event) => setSelectedFile(event.target.files?.[0] || null)} disabled={!selectedCaseId || isBusy} />
              <Button type="submit" className="w-full" disabled={!canUpload || isBusy}>Upload Evidence</Button>
            </form>
            <p className="text-xs text-slate-500">Accepted: .txt, .log, .csv, .json (5MB)</p>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FileBarChart2 className="h-4 w-4" /> Evidence & Analysis</CardTitle>
            <CardDescription>Quick actions with clearer file context.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={enrichWithPlaywright} onChange={(event) => setEnrichWithPlaywright(event.target.checked)} disabled={isBusy} />
              Live URL enrichment with Playwright (optional)
            </label>
            <div className="flex gap-2">
              <Input
                value={manualUrl}
                onChange={(event) => setManualUrl(event.target.value)}
                placeholder="https://example.com/suspicious-path"
                disabled={isBusy}
              />
              <Button
                variant="outline"
                onClick={enrichManualUrl}
                disabled={isBusy || !manualUrl.trim()}
              >
                Enrich URL
              </Button>
            </div>
            {urlFindings.length > 0 && (
              <div className="max-h-36 space-y-2 overflow-auto rounded-md border border-slate-200 p-2">
                {urlFindings.map((finding) => (
                  <div key={`${finding.url}-${finding.finalUrl || "none"}-${finding.title}`} className="rounded-md bg-slate-50 p-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-xs font-medium text-slate-700">{finding.url}</p>
                      <Badge variant={urlVerdict(finding).tone}>{urlVerdict(finding).label}</Badge>
                    </div>
                    <p className="text-[11px] text-slate-600">
                      status: {finding.status ?? "n/a"} | https: {finding.usesHttps ? "yes" : "no"} | redirected: {finding.redirected ? "yes" : "no"}
                    </p>
                    <p className="text-[11px] text-slate-600">
                      host: {finding.hostname || "unknown"} | path: {finding.path || "/"}
                    </p>
                    <p className="text-[11px] text-slate-500">title: {finding.title || "untitled"}</p>
                    <p className="text-[11px] text-slate-500">content-type: {finding.contentType || "unknown"}</p>
                    <p className="text-[11px] text-slate-500">final: {finding.finalUrl || "unreachable"}</p>
                    {finding.snippet && <p className="rounded bg-white p-1 font-mono text-[11px] text-slate-700">{finding.snippet}</p>}
                    {finding.error && <p className="text-[11px] text-red-700">error: {finding.error}</p>}
                    {String(finding.finalUrl || "").includes("supabase.com") && (
                      <p className="text-[11px] text-amber-700">
                        Note: dashboard URLs are typically auth-protected; preview may only show login/redirect page.
                      </p>
                    )}
                    <p className="text-[10px] text-slate-400">inspected: {formatDate(finding.inspectedAt)}</p>
                  </div>
                ))}
              </div>
            )}
            <Button className="w-full" onClick={runCaseAnalysis} disabled={!selectedCaseId || isBusy || evidence.length === 0}>Analyze All Evidence</Button>
            <div className="max-h-72 space-y-2 overflow-auto pr-1">
              {evidence.length === 0 && <p className="text-sm text-slate-500">No evidence uploaded yet.</p>}
              {evidence.map((item) => (
                <div key={item.id} className="rounded-md border border-slate-200 p-3">
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-medium">{item.filename}</p>
                    <div className="flex gap-2">
                      <Badge variant="secondary">{item.logFormat || "text"}</Badge>
                      <Badge variant="secondary">{item.providerHint || "generic"}</Badge>
                    </div>
                  </div>
                  <p className="text-xs text-slate-500">{formatDate(item.createdAt)}</p>
                  <p className="mt-2 rounded-md bg-slate-50 p-2 font-mono text-[11px] text-slate-700">
                    {(item.previewLog || "No preview available").slice(0, 420)}
                  </p>
                  <div className="mt-2 flex gap-2">
                    <Button size="sm" onClick={() => runAnalysis(item.id)} disabled={isBusy}>Analyze</Button>
                    <Button size="sm" variant="outline" onClick={() => deleteEvidence(item.id)} disabled={isBusy}>Delete</Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> Analysis Insights</CardTitle>
            <CardDescription>Actionable findings with score, density, and log context.</CardDescription>
          </CardHeader>
          <CardContent className="max-h-96 space-y-3 overflow-auto pr-1">
            {analyses.length === 0 && <p className="text-sm text-slate-500">No analyses available.</p>}
            {analyses.map((entry) => (
              <div key={entry.id} className="rounded-md border border-slate-200 p-3">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <p className="text-sm font-semibold">{entry.evidenceFilename}</p>
                  <Badge variant={summaryVariant(riskFromScore(Number(entry.threatScore || 0)))}>
                    {riskFromScore(Number(entry.threatScore || 0)).toUpperCase()} {entry.threatScore}
                  </Badge>
                </div>
                <p className="text-xs text-slate-600">
                  {entry.iocCount} IOC hit(s) across {entry.lineCount} parsed line(s) | density{" "}
                  {entry.lineCount ? (entry.iocCount / entry.lineCount).toFixed(2) : "0.00"} IOC/line
                </p>
                <p className="mt-1 text-xs text-slate-500">{entry.summary}</p>
                <p className="mt-2 rounded-md bg-slate-50 p-2 font-mono text-[11px] text-slate-700">
                  {(evidenceById.get(Number(entry.evidenceId))?.previewLog || "No log preview available").slice(0, 420)}
                </p>
                {Array.isArray(entry.playwrightFindings) && entry.playwrightFindings.length > 0 && (
                  <div className="mt-2 space-y-1 rounded-md border border-slate-200 bg-white p-2">
                    <p className="text-[11px] font-semibold text-slate-700">URL Enrichment Findings</p>
                    {entry.playwrightFindings.slice(0, 3).map((finding) => (
                      <div key={`${entry.id}-${finding.url}-${finding.finalUrl || "none"}`} className="rounded bg-slate-50 p-2">
                        <p className="text-[11px] font-medium text-slate-700">{finding.url}</p>
                        <p className="text-[11px] text-slate-600">
                          status: {finding.status ?? "n/a"} | title: {finding.title || "untitled"}
                        </p>
                        <p className="text-[11px] text-slate-500">final: {finding.finalUrl || "unreachable"}</p>
                      </div>
                    ))}
                  </div>
                )}
                <p className="mt-1 text-[11px] text-slate-400">Generated {formatDate(entry.createdAt)}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      <Card>
        <CardHeader>
          <CardTitle>Top Findings</CardTitle>
          <CardDescription>Highest-risk evidence sorted by threat score and IOC volume.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {!report?.topFindings?.length && <p className="text-sm text-slate-500">No findings yet.</p>}
          {report?.topFindings?.map((finding) => (
            <div key={`${finding.evidenceFilename}-${finding.createdAt}`} className="rounded-md border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium">{finding.evidenceFilename}</p>
                <Badge variant={summaryVariant(riskFromScore(Number(finding.threatScore || 0)))}>
                  score {finding.threatScore}
                </Badge>
              </div>
              <p className="text-xs text-slate-600">{finding.iocCount} IOC hit(s)</p>
              <p className="mt-1 text-xs text-slate-500">{finding.summary}</p>
            </div>
          ))}
        </CardContent>
      </Card>

      <section className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Threat & IOC by Evidence</CardTitle></CardHeader>
          <CardContent className="h-72">
            {topThreatRows.length === 0 ? (
              <p className="text-sm text-slate-500">Run analysis to generate chart.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topThreatRows}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="threatScore" fill="#334155" name="Threat Score" />
                  <Bar dataKey="iocCount" fill="#0ea5e9" name="IOC Hits" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Timeline & Provider Charts</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="h-40">
              {timelineByHour.length === 0 ? (
                <p className="text-sm text-slate-500">No timeline data yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={timelineByHour}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="hour" />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="events" stroke="#16a34a" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
            <div className="h-28">
              {providerDist.length === 0 ? (
                <p className="text-sm text-slate-500">No provider split yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={providerDist} layout="vertical">
                    <XAxis type="number" />
                    <YAxis type="category" dataKey="provider" width={80} />
                    <Tooltip />
                    <Bar dataKey="files" fill="#7c3aed" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
            <CardDescription>How many analysis results fall into each risk band.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {analyses.length === 0 ? (
              <p className="text-sm text-slate-500">Run analysis to generate risk distribution.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskDistribution}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="risk" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#ef4444" name="Analyses" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Analysis Trend</CardTitle>
            <CardDescription>Recent threat-score progression with IOC count context.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {scoreTrend.length === 0 ? (
              <p className="text-sm text-slate-500">No trend data yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={scoreTrend}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="at" hide />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="threatScore" stroke="#0f172a" strokeWidth={2} name="Threat Score" />
                  <Line type="monotone" dataKey="iocCount" stroke="#0891b2" strokeWidth={2} name="IOC Hits" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </section>

      <Card>
        <CardHeader><CardTitle>Timeline Search</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <Input value={timelineQuery} onChange={(event) => setTimelineQuery(event.target.value)} placeholder="Filter timeline by keyword..." disabled={!selectedCaseId || isBusy} />
          <div className="max-h-56 space-y-2 overflow-auto pr-1">
            {timeline.length === 0 && <p className="text-sm text-slate-500">No events extracted yet.</p>}
            {timeline.map((event) => (
              <div key={event.id} className="rounded-md border border-slate-200 p-2">
                <p className="text-xs font-medium">{formatDate(event.eventTime)}</p>
                <p className="text-xs text-slate-600">{event.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
          <p className="text-sm text-slate-600">
            <AlertTriangle className="mr-1 inline h-4 w-4" />
            {status.message}
          </p>
          <Button variant="secondary" onClick={exportReportJson} disabled={isBusy || !report}>Export Report JSON</Button>
        </CardContent>
      </Card>
    </main>
  );
}

export default App;
