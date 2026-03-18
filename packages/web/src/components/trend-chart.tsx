"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface DataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
}

export function TrendChart({ data }: { data: DataPoint[] }) {
  return (
    <div className="bg-[#1a1a2e] rounded-xl p-6">
      <h2 className="text-lg font-semibold mb-4">Vulnerability Trend</h2>
      <div className="h-[250px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="criticalGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ff4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff8c00" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ff8c00" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ffd700" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ffd700" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="date"
              stroke="#555"
              fontSize={12}
              tickLine={false}
            />
            <YAxis
              stroke="#555"
              fontSize={12}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "#1a1a2e",
                border: "1px solid #333",
                borderRadius: "8px",
                color: "#e0e0e0",
              }}
            />
            <Area
              type="monotone"
              dataKey="critical"
              stroke="#ff4444"
              fill="url(#criticalGrad)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="high"
              stroke="#ff8c00"
              fill="url(#highGrad)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="medium"
              stroke="#ffd700"
              fill="url(#medGrad)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
