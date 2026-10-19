import { api } from "./api";
import { fields, intelligence, providers } from "./contracts";
export async function listThreats(params, signal) {
  const { data } = await api.get("/threats", { params, signal });
  fields(data, {
    items: "array",
    total: "number",
    limit: "number",
    offset: "number",
  });
  data.items.forEach(intelligence);
  return data;
}
export async function lookupThreat(ip) {
  const { data } = await api.post("/threats/lookup", {
    ip,
    force_refresh: false,
  });
  return intelligence(data);
}
export async function getProviders(signal) {
  const { data } = await api.get("/threats/providers/status", { signal });
  return providers(data);
}
