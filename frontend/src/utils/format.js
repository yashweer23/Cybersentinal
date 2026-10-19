export const number = (value, digits = 0) =>
  value == null
    ? "—"
    : new Intl.NumberFormat("en-US", { maximumFractionDigits: digits }).format(
        value,
      );
export const label = (value) =>
  String(value ?? "Unknown")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
export function utc(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Invalid timestamp"
    : `${date.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}
export function shortTime(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: "UTC",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}
export const severityColor = {
  CRITICAL: "#ff7585",
  HIGH: "#f8b76b",
  MEDIUM: "#e3ce77",
  LOW: "#69d7ba",
};
export const riskLevel = (value) =>
  value >= 75
    ? "CRITICAL"
    : value >= 50
      ? "HIGH"
      : value >= 25
        ? "MEDIUM"
        : "LOW";
