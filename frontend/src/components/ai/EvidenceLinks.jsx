import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FileSearch } from "lucide-react";
import { getFinding, getRisk } from "../../services/incidentsApi";
import { QueryState } from "../common/UI";
import Dialog from "../incidents/Dialog";
import EventDetailDrawer from "../incidents/EventDetailDrawer";
import RiskBreakdown from "../incidents/RiskBreakdown";
import { EvidenceFields } from "../incidents/EvidenceFields";
function Detail({ reference, close }) {
  const risk = reference.kind === "risk";
  const query = useQuery({
    queryKey: [risk ? "risk" : "finding", reference.reference_id],
    queryFn: ({ signal }) =>
      (risk ? getRisk : getFinding)(reference.reference_id, signal),
  });
  return (
    <Dialog
      title={risk ? "Stored risk assessment" : "Detection finding evidence"}
      onClose={close}
      drawer
    >
      <p className="mono case-event-id">{reference.reference_id}</p>
      <QueryState query={query}>
        {(data) =>
          risk ? (
            <RiskBreakdown assessment={data} />
          ) : (
            <>
              <p>{data.description}</p>
              <EvidenceFields data={data.evidence_data} />
            </>
          )
        }
      </QueryState>
    </Dialog>
  );
}
export default function EvidenceLinks({ ids, references, incidentId }) {
  const [selected, setSelected] = useState(null);
  return (
    <>
      <div className="ai-reference-links">
        {ids.map((id) => {
          const ref = references.find((r) => r.reference_id === id);
          if (!ref) return null;
          if (["event", "finding", "risk"].includes(ref.kind))
            return (
              <button
                key={id}
                className="text-button ai-evidence-link"
                title={id}
                aria-label={`View evidence ${id}`}
                onClick={() => setSelected(ref)}
              >
                <FileSearch size={13} />
                {ref.label}
              </button>
            );
          const tab =
            ref.kind === "indicator"
              ? "threat-intelligence"
              : ref.kind === "audit"
                ? "timeline"
                : "overview";
          return (
            <Link
              key={id}
              title={id}
              className="panel-link ai-evidence-link"
              to={`/incidents/${encodeURIComponent(incidentId)}?tab=${tab}`}
            >
              <FileSearch size={13} />
              {ref.label}
            </Link>
          );
        })}
      </div>
      {selected?.kind === "event" && (
        <EventDetailDrawer
          eventId={selected.reference_id}
          close={() => setSelected(null)}
        />
      )}
      {selected && selected.kind !== "event" && (
        <Detail reference={selected} close={() => setSelected(null)} />
      )}
    </>
  );
}
