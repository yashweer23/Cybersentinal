import { api } from "./api";
import { assert, fields } from "./contracts";
export async function getRules(signal) {
  const { data } = await api.get("/detection-rules", {
    params: { limit: 100 },
    signal,
  });
  assert(Array.isArray(data));
  data.forEach((row) =>
    fields(row, {
      rule_id: "string",
      name: "string",
      description: "string",
      severity: "string",
      enabled: "boolean",
      configuration: "object",
    }),
  );
  return data;
}
export async function setRuleEnabled(ruleId, enabled) {
  const { data } = await api.patch(
    `/detection-rules/${encodeURIComponent(ruleId)}`,
    { enabled },
  );
  return fields(data, { rule_id: "string", enabled: "boolean" });
}
