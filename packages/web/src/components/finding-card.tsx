import { SeverityBadge } from "./severity-badge";
import type { Finding } from "@/lib/demo-data";

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div
      className={`bg-[#1a1a2e] rounded-xl p-5 border-l-4 ${
        finding.severity === "critical"
          ? "border-red-500"
          : finding.severity === "high"
            ? "border-orange-500"
            : finding.severity === "medium"
              ? "border-yellow-400"
              : "border-blue-400"
      }`}
    >
      <div className="flex items-center gap-3 mb-2 flex-wrap">
        <SeverityBadge severity={finding.severity} />
        <span className="text-gray-500 text-sm">{finding.rule}</span>
        {finding.source !== "custom" && (
          <span className="text-xs px-2 py-0.5 rounded bg-purple-900/50 text-purple-300">
            {finding.source}
          </span>
        )}
        <span className="font-semibold">{finding.title}</span>
      </div>

      <div className="text-cyan-400 text-sm font-mono mb-2">
        {finding.file}:{finding.line}
      </div>

      <p className="text-gray-400 text-sm mb-3 leading-relaxed">
        {finding.description}
      </p>

      {finding.snippet && (
        <pre className="bg-[#12121f] rounded-lg p-3 text-xs font-mono overflow-x-auto text-gray-400 mb-3 whitespace-pre">
          {finding.snippet.split("\n").map((line, i) => (
            <span key={i} className={line.startsWith(">") ? "text-red-400 font-bold" : ""}>
              {line}
              {"\n"}
            </span>
          ))}
        </pre>
      )}

      {finding.fix && (
        <div className="bg-green-900/20 rounded-lg p-3 text-sm text-green-400">
          <span className="font-bold">Fix: </span>
          {finding.fix}
        </div>
      )}
    </div>
  );
}
