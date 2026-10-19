import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState } from "../common/UI";
import {
  label,
  number,
  severityColor,
  shortTime,
  utc,
} from "../../utils/format";
export function ChartTooltip({ active, payload, label: title }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <strong>
        {typeof title === "string" && /^\d{4}-/.test(title)
          ? utc(title)
          : label(title ?? payload[0].name)}
      </strong>
      {payload.map((p, i) => (
        <div key={i}>
          <i style={{ background: p.color || p.payload?.fill || "#6be2b5" }} />
          <span>{label(p.name)}</span>
          <b>{number(p.value)}</b>
        </div>
      ))}
    </div>
  );
}
const grid = { stroke: "#26313c", strokeDasharray: "3 5", vertical: false };
const axis = {
  tick: { fill: "#99a8b7", fontSize: 10 },
  axisLine: false,
  tickLine: false,
};
export function SecurityTimeline({ data }) {
  if (!data.total) return <EmptyState title="No events in this period" />;
  return (
    <>
      <div className="chart-legend">
        <span>
          <i style={{ background: "#6be2b5" }} />
          Total events
        </span>
        <span>
          <i style={{ background: "#ff7585" }} />
          Failed logins
        </span>
        <span>
          <i style={{ background: "#f8b76b" }} />
          Access denied
        </span>
        <span className="legend-total">{number(data.total)} events · UTC</span>
      </div>
      <div className="chart-wrap timeline-chart">
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart
            data={data.data}
            margin={{ top: 14, right: 15, left: -18, bottom: 0 }}
            accessibilityLayer
          >
            <CartesianGrid {...grid} />
            <XAxis
              {...axis}
              dataKey="timestamp"
              tickFormatter={shortTime}
              minTickGap={55}
            />
            <YAxis
              {...axis}
              allowDecimals={false}
              tickFormatter={(v) => number(v)}
            />
            <Tooltip content={<ChartTooltip />} />
            <Area
              type="monotone"
              dataKey="total"
              name="Total events"
              stroke="#6be2b5"
              fill="#6be2b5"
              fillOpacity={0.09}
              strokeWidth={2}
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="login_failed"
              name="Failed logins"
              stroke="#ff7585"
              fill="transparent"
              strokeWidth={1.5}
              isAnimationActive={false}
            />
            <Area
              type="monotone"
              dataKey="access_denied"
              name="Access denied"
              stroke="#f8b76b"
              fill="transparent"
              strokeWidth={1.5}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </>
  );
}
export function SeverityChart({ data }) {
  if (!data.total) return <EmptyState title="No incidents in this period" />;
  return (
    <div className="severity-content">
      <div className="donut-wrap">
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <PieChart>
            <Pie
              data={data.distribution}
              dataKey="count"
              nameKey="severity"
              innerRadius="68%"
              outerRadius="92%"
              paddingAngle={
                data.distribution.filter((d) => d.count > 0).length > 1 ? 3 : 0
              }
              stroke="none"
              isAnimationActive={false}
            >
              {data.distribution.map((d) => (
                <Cell
                  key={d.severity}
                  fill={severityColor[d.severity] || "#8594aa"}
                />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <strong>{number(data.total)}</strong>
          <span>INCIDENTS</span>
        </div>
      </div>
      <div className="severity-legend">
        {data.distribution.map((d) => (
          <div key={d.severity}>
            <span>
              <i style={{ background: severityColor[d.severity] }} />
              {label(d.severity)}
            </span>
            <b>{number(d.count)}</b>
          </div>
        ))}
      </div>
    </div>
  );
}
export function DistributionBars({
  data,
  dataKey = "level",
  colors = false,
  emptyTitle,
}) {
  if (!data.distribution.some((d) => d.count > 0))
    return <EmptyState title={emptyTitle || "No records in this period"} />;
  return (
    <div
      className="chart-wrap distribution-chart"
      style={{ height: Math.max(210, data.distribution.length * 35) }}
    >
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <BarChart
          data={data.distribution}
          layout="vertical"
          margin={{ top: 8, right: 28, left: 10, bottom: 8 }}
          accessibilityLayer
        >
          <CartesianGrid {...grid} horizontal={false} vertical />
          <XAxis {...axis} type="number" allowDecimals={false} />
          <YAxis
            {...axis}
            type="category"
            dataKey={dataKey}
            width={dataKey === "event_type" ? 145 : 98}
            tickFormatter={label}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "#ffffff05" }} />
          <Bar
            dataKey="count"
            name="Records"
            radius={[0, 3, 3, 0]}
            barSize={12}
            isAnimationActive={false}
          >
            {data.distribution.map((d) => (
              <Cell
                key={d[dataKey]}
                fill={
                  colors ? severityColor[d[dataKey]] || "#6be2b5" : "#6be2b5"
                }
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
