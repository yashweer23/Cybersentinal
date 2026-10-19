import { useState } from "react";
import { useIncidentMutation } from "../../hooks/useIncident";
import { changeIncidentStatus } from "../../services/incidentsApi";
import { ErrorState } from "../common/UI";
import Dialog from "./Dialog";

export function statusAction(status, current) {
  return status === "RESOLVED"
    ? "Resolve incident"
    : status === "FALSE_POSITIVE"
      ? "Mark false positive"
      : current === "OPEN"
        ? "Start investigation"
        : "Reopen incident";
}
export default function StatusControl({ incident, target, close, notify }) {
  const [note, setNote] = useState("");
  const required = ["RESOLVED", "FALSE_POSITIVE"].includes(target);
  const title = statusAction(target, incident.status);
  const field =
    target === "RESOLVED"
      ? "Resolution summary"
      : target === "FALSE_POSITIVE"
        ? "False-positive reason"
        : "Investigation note (optional)";
  const mutation = useIncidentMutation(
    incident.incident_id,
    "status",
    (payload) => changeIncidentStatus(incident.incident_id, payload),
    () => {
      notify("Incident status updated.");
      close();
    },
  );
  const allowed = incident.allowed_transitions.includes(target);
  const submit = (event) => {
    event.preventDefault();
    if (!allowed || mutation.isPending || (required && !note.trim())) return;
    const payload = { status: target };
    if (note.trim())
      payload[target === "RESOLVED" ? "resolution_summary" : "reason"] =
        note.trim();
    mutation.mutate(payload);
  };
  return (
    <Dialog title={title} onClose={close} busy={mutation.isPending}>
      <p>
        Change <strong>{incident.incident_id}</strong> from{" "}
        <strong>{incident.status}</strong> to <strong>{target}</strong>. This
        action is recorded in the case timeline.
      </p>
      {!allowed && (
        <p className="info-note" role="alert">
          The case changed while this dialog was open. Close it and review the
          current status.
        </p>
      )}
      <form onSubmit={submit}>
        <label>
          {field}
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            required={required}
            maxLength={4000}
            rows={5}
            disabled={mutation.isPending}
          />
        </label>
        <p className="case-small muted">
          {note.length}/4,000 characters · Evidence is retained.
        </p>
        {mutation.isError && <ErrorState error={mutation.error} />}
        <div className="case-dialog-actions">
          <button
            type="button"
            className="button secondary"
            disabled={mutation.isPending}
            onClick={close}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="button"
            disabled={
              !allowed || mutation.isPending || (required && !note.trim())
            }
          >
            {mutation.isPending ? "Saving…" : `Confirm ${title.toLowerCase()}`}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
