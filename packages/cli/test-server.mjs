import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = resolve(__dirname, "dist/index.js");
const testAppPath = resolve(__dirname, "../../test-app");

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatSnippetHtml(snippet) {
  return snippet
    .split("\n")
    .map((line) => {
      if (line.startsWith(">")) {
        return '<span class="highlight">' + escapeHtml(line) + "</span>";
      }
      return escapeHtml(line);
    })
    .join("\n");
}

function getScanResult() {
  try {
    const output = execFileSync(
      "node",
      [cliPath, "scan", testAppPath, "--no-ai", "--format", "json"],
      { encoding: "utf-8", timeout: 10000 }
    );
    return JSON.parse(output);
  } catch (e) {
    if (e.stdout) {
      return JSON.parse(e.stdout);
    }
    return { findings: [], filesScanned: 0 };
  }
}

function buildFindingCard(f) {
  let card = '<div class="finding ' + f.severity + '">';
  card += '<div class="finding-header">';
  card += '<span class="badge ' + f.severity + '">' + f.severity + "</span>";
  card += '<span class="rule-id">' + f.rule + "</span>";
  if (f.source !== "custom") {
    card += '<span class="source-tag">' + f.source + "</span>";
  }
  card += '<span class="finding-title">' + escapeHtml(f.title) + "</span>";
  card += "</div>";
  card +=
    '<div class="finding-file">' +
    escapeHtml(f.file) +
    ":" +
    f.line +
    "</div>";
  card +=
    '<div class="finding-desc">' + escapeHtml(f.description) + "</div>";
  if (f.snippet) {
    card +=
      '<div class="snippet">' + formatSnippetHtml(f.snippet) + "</div>";
  }
  if (f.fix) {
    card += '<div class="fix">' + escapeHtml(f.fix) + "</div>";
  }
  card += "</div>";
  return card;
}

const server = createServer((req, res) => {
  if (req.url === "/" || req.url === "/index.html") {
    const scanResult = getScanResult();

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of scanResult.findings) counts[f.severity]++;

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = scanResult.findings
      .slice()
      .sort((a, b) => order[a.severity] - order[b.severity]);

    const findingsHtml = sorted.map(buildFindingCard).join("\n    ");

    const html = [
      "<!DOCTYPE html>",
      '<html lang="en">',
      "<head>",
      '  <meta charset="utf-8">',
      '  <meta name="viewport" content="width=device-width, initial-scale=1">',
      "  <title>VibeCheck - Scan Results</title>",
      "  <style>",
      "    * { margin: 0; padding: 0; box-sizing: border-box; }",
      "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; padding: 2rem; }",
      "    .header { text-align: center; margin-bottom: 2rem; }",
      "    .header h1 { font-size: 2rem; color: #00d4ff; }",
      "    .header p { color: #888; margin-top: 0.5rem; }",
      "    .summary { display: flex; gap: 1rem; justify-content: center; margin-bottom: 2rem; flex-wrap: wrap; }",
      "    .stat { background: #1a1a2e; border-radius: 12px; padding: 1rem 1.5rem; text-align: center; min-width: 100px; }",
      "    .stat .count { font-size: 2rem; font-weight: bold; }",
      "    .stat .label { font-size: 0.75rem; text-transform: uppercase; color: #888; margin-top: 0.25rem; }",
      "    .stat.critical .count { color: #ff4444; }",
      "    .stat.high .count { color: #ff8c00; }",
      "    .stat.medium .count { color: #ffd700; }",
      "    .stat.low .count { color: #4da6ff; }",
      "    .stat.files .count { color: #00d4ff; }",
      "    .findings { max-width: 800px; margin: 0 auto; }",
      "    .finding { background: #1a1a2e; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid; }",
      "    .finding.critical { border-color: #ff4444; }",
      "    .finding.high { border-color: #ff8c00; }",
      "    .finding.medium { border-color: #ffd700; }",
      "    .finding.low { border-color: #4da6ff; }",
      "    .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }",
      "    .badge { padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }",
      "    .badge.critical { background: #ff4444; color: #fff; }",
      "    .badge.high { background: #ff8c00; color: #fff; }",
      "    .badge.medium { background: #ffd700; color: #000; }",
      "    .badge.low { background: #4da6ff; color: #fff; }",
      "    .rule-id { color: #888; font-size: 0.8rem; }",
      "    .finding-title { font-weight: 600; font-size: 1rem; }",
      "    .finding-file { color: #00d4ff; font-size: 0.85rem; margin-bottom: 0.5rem; font-family: monospace; }",
      "    .finding-desc { color: #bbb; font-size: 0.9rem; line-height: 1.5; margin-bottom: 0.75rem; }",
      "    .snippet { background: #12121f; border-radius: 8px; padding: 0.75rem; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre; color: #999; margin-bottom: 0.75rem; }",
      "    .snippet .highlight { color: #ff6b6b; font-weight: bold; }",
      "    .fix { background: #0d2818; border-radius: 8px; padding: 0.75rem; font-size: 0.85rem; color: #4ade80; line-height: 1.5; }",
      "    .fix::before { content: 'Fix: '; font-weight: 700; }",
      "    .source-tag { font-size: 0.7rem; padding: 0.15rem 0.4rem; border-radius: 4px; background: #2a1a4e; color: #a78bfa; }",
      "  </style>",
      "</head>",
      "<body>",
      '  <div class="header">',
      "    <h1>vibecheck</h1>",
      "    <p>AI security scanner for vibe-coded apps</p>",
      "  </div>",
      '  <div class="summary">',
      '    <div class="stat files">',
      '      <div class="count">' + scanResult.filesScanned + "</div>",
      '      <div class="label">Files Scanned</div>',
      "    </div>",
      '    <div class="stat critical">',
      '      <div class="count">' + counts.critical + "</div>",
      '      <div class="label">Critical</div>',
      "    </div>",
      '    <div class="stat high">',
      '      <div class="count">' + counts.high + "</div>",
      '      <div class="label">High</div>',
      "    </div>",
      '    <div class="stat medium">',
      '      <div class="count">' + counts.medium + "</div>",
      '      <div class="label">Medium</div>',
      "    </div>",
      '    <div class="stat low">',
      '      <div class="count">' + counts.low + "</div>",
      '      <div class="label">Low</div>',
      "    </div>",
      "  </div>",
      '  <div class="findings">',
      "    " + findingsHtml,
      "  </div>",
      "</body>",
      "</html>",
    ].join("\n");

    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  } else {
    res.writeHead(404);
    res.end("Not found");
  }
});

const PORT = 3847;
server.listen(PORT, () => {
  console.log("VibeCheck results server running at http://localhost:" + PORT);
});
