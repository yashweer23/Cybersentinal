import { useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext";
import { useIncident } from "../hooks/useIncident";
import { EmptyState, QueryState } from "../components/common/UI";
import IncidentHeader from "../components/incidents/IncidentHeader";
import IncidentOverview from "../components/incidents/IncidentOverview";
import FindingsPanel from "../components/incidents/FindingsPanel";
import IncidentTimeline from "../components/incidents/IncidentTimeline";
import IncidentEvents from "../components/incidents/IncidentEvents";
import IncidentComments from "../components/incidents/IncidentComments";
import ThreatIntelligencePanel from "../components/incidents/ThreatIntelligencePanel";
import AssignmentControl from "../components/incidents/AssignmentControl";
import StatusControl from "../components/incidents/StatusControl";
import "../investigation.css";
import AIAnalysisPanel from "../components/ai/AIAnalysisPanel";
const tabs = [
  ["overview", "Overview"],
  ["timeline", "Timeline"],
  ["findings", "Findings"],
  ["events", "Events"],
  ["threat-intelligence", "Threat intel"],
  ["notes", "Notes"],
  ["ai-analysis", "AI Analysis"],
];
export default function IncidentInvestigation() {
  const { incident_id } = useParams();
  return <Investigation key={incident_id} id={incident_id} />;
}
function Investigation({ id }) {
  const { user } = useAuth();
  const query = useIncident(id),
    client = useQueryClient();
  const [search, setSearch] = useSearchParams();
  const selected = search.get("tab");
  const active = tabs.some(([value]) => value === selected)
    ? selected
    : "overview";
  const backTo = /^\/incidents(?:\?[^#]*)?$/.test(search.get("returnTo") || "")
    ? search.get("returnTo")
    : "/incidents";
  const [dialog, setDialog] = useState(null),
    [message, setMessage] = useState(""),
    [draftNote, setDraftNote] = useState("");
  const tablist = useRef(null);
  const canWrite = ["ADMIN", "ANALYST"].includes(user.role);
  const openTab = (tab) => {
    const next = new URLSearchParams(search);
    next.set("tab", tab);
    setSearch(next, { replace: true });
  };
  function keyboard(event, index) {
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft")
      next = (index + tabs.length - 1) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    openTab(tabs[next][0]);
    tablist.current.querySelectorAll('[role="tab"]')[next].focus();
  }
  if (query.error?.response?.status === 404)
    return (
      <>
        <EmptyState
          title="Incident not found"
          description="This incident ID does not exist or is no longer available."
        />
        <Link className="button secondary" to={backTo}>
          Back to incidents
        </Link>
      </>
    );
  return (
    <div className="case-workspace">
      <QueryState query={query}>
        {(incident) => (
          <>
            <IncidentHeader
              incident={incident}
              canWrite={canWrite && !query.isError}
              backTo={backTo}
              busy={query.isFetching}
              refresh={() =>
                void client.invalidateQueries({ queryKey: ["incident", id] })
              }
              onAnalyze={() => openTab("ai-analysis")}
              onAssign={() => {
                setMessage("");
                setDialog("assign");
              }}
              onStatus={(target) => {
                setMessage("");
                setDialog(target);
              }}
              onNote={() => {
                openTab("notes");
                requestAnimationFrame(() =>
                  document.getElementById("case-note-input")?.focus(),
                );
              }}
            />
            {message && (
              <p className="case-success" role="status">
                {message}
              </p>
            )}
            <div
              className="case-tabs"
              role="tablist"
              aria-label="Incident investigation"
              ref={tablist}
            >
              {tabs.map(([key, title], index) => (
                <button
                  key={key}
                  role="tab"
                  id={`tab-${key}`}
                  aria-controls="case-tab-panel"
                  aria-selected={active === key}
                  tabIndex={active === key ? 0 : -1}
                  onClick={() => openTab(key)}
                  onKeyDown={(event) => keyboard(event, index)}
                >
                  {title}
                  {key === "findings" && <span>{incident.findings.total}</span>}
                </button>
              ))}
            </div>
            <div
              id="case-tab-panel"
              role="tabpanel"
              aria-labelledby={`tab-${active}`}
              tabIndex={0}
            >
              {active === "ai-analysis" && (
                <AIAnalysisPanel key={id} incidentId={id} />
              )}
              {active === "overview" && (
                <IncidentOverview incident={incident} openTab={openTab} />
              )}
              {active === "timeline" && <IncidentTimeline incidentId={id} />}
              {active === "findings" && <FindingsPanel incidentId={id} />}
              {active === "events" && <IncidentEvents incidentId={id} />}
              {active === "threat-intelligence" && (
                <ThreatIntelligencePanel incidentId={id} />
              )}
              {active === "notes" && (
                <IncidentComments
                  incidentId={id}
                  draft={draftNote}
                  setDraft={setDraftNote}
                />
              )}
            </div>
            {canWrite && dialog === "assign" && (
              <AssignmentControl
                incident={incident}
                close={() => setDialog(null)}
                notify={setMessage}
              />
            )}
            {canWrite && dialog && dialog !== "assign" && (
              <StatusControl
                incident={incident}
                target={dialog}
                close={() => setDialog(null)}
                notify={setMessage}
              />
            )}
          </>
        )}
      </QueryState>
    </div>
  );
}
