import {
  LineChart,
  Line,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { EmptyState } from "../common/UI";
import { ChartTooltip } from "../dashboard/Charts";
import { number, shortTime } from "../../utils/format";
const colors = ["#6be2b5", "#ff7585", "#8faaff", "#f8b76b", "#c5a1f5"];
const axis = {
  tick: { fill: "#99a8b7", fontSize: 10 },
  axisLine: false,
  tickLine: false,
};
export function TrendChart({
  data,
  series,
  domain,
  empty = "No activity in this period",
}) {
  if (
    !data.some(
      (row) =>
        row.count > 0 ||
        series.some(([key]) => row[key] != null && row[key] !== 0),
    )
  )
    return <EmptyState title={empty} />;
  return (
    <div className="chart-wrap analytics-chart">
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <LineChart
          data={data}
          margin={{ top: 12, right: 16, left: -12, bottom: 4 }}
          accessibilityLayer
        >
          <CartesianGrid
            stroke="#26313c"
            strokeDasharray="3 5"
            vertical={false}
          />
          <XAxis
            {...axis}
            dataKey="timestamp"
            tickFormatter={shortTime}
            minTickGap={55}
          />
          <YAxis
            {...axis}
            domain={domain || [0, "auto"]}
            tickFormatter={(v) => number(v, 1)}
          />
          <Tooltip content={<ChartTooltip />} />
          <Legend />
          {series.map(([key, name], i) => (
            <Line
              key={key}
              dataKey={key}
              name={name}
              stroke={colors[i % colors.length]}
              strokeWidth={2}
              dot={domain ? { r: 3, strokeWidth: 1 } : false}
              connectNulls={false}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
export function ComparisonChart({ data, category, series }) {
  if (!data.some((row) => series.some(([key]) => row[key] > 0)))
    return <EmptyState title="No matching records in this period" />;
  return (
    <div className="chart-wrap analytics-chart">
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <BarChart
          data={data}
          margin={{ top: 12, right: 16, left: -10, bottom: 16 }}
          accessibilityLayer
        >
          <CartesianGrid
            stroke="#26313c"
            strokeDasharray="3 5"
            vertical={false}
          />
          <XAxis
            {...axis}
            dataKey={category}
            interval={0}
            tick={{ ...axis.tick, fontSize: 9 }}
          />
          <YAxis {...axis} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} />
          <Legend />
          {series.map(([key, name], i) => (
            <Bar
              key={key}
              dataKey={key}
              name={name}
              fill={colors[i % colors.length]}
              radius={[3, 3, 0, 0]}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
