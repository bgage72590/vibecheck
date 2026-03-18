export function StatCard({
  label,
  value,
  color = "text-cyan-400",
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="bg-[#1a1a2e] rounded-xl p-4 text-center min-w-[100px]">
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      <div className="text-xs uppercase text-gray-500 mt-1">{label}</div>
    </div>
  );
}
