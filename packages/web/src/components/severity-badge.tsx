const styles: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-400 text-black",
  low: "bg-blue-400 text-white",
  info: "bg-gray-500 text-white",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-bold uppercase ${styles[severity] ?? styles.info}`}
    >
      {severity}
    </span>
  );
}
