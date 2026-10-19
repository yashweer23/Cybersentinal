import { useState } from "react";
import { useAuth } from "../../context/AuthContext";
import {
  useIncidentMutation,
  useIncidentSection,
} from "../../hooks/useIncident";
import { addIncidentComment } from "../../services/incidentsApi";
import {
  Badge,
  EmptyState,
  ErrorState,
  Pagination,
  Panel,
  QueryState,
} from "../common/UI";
import { utc } from "../../utils/format";
export default function IncidentComments({ incidentId, draft, setDraft }) {
  const { user } = useAuth();
  const canWrite = ["ADMIN", "ANALYST"].includes(user.role);
  const [offset, setOffset] = useState(0),
    [message, setMessage] = useState("");
  const query = useIncidentSection(incidentId, "comments", {
    limit: 20,
    offset,
  });
  const mutation = useIncidentMutation(
    incidentId,
    "comment",
    (text) => addIncidentComment(incidentId, text),
    () => {
      setDraft("");
      setMessage("Investigation note saved.");
    },
  );
  return (
    <Panel
      title="Analyst notes"
      subtitle="Recorded observations and investigation decisions"
    >
      <div className="case-content">
        {canWrite && (
          <form
            className="case-note-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (draft.trim() && !mutation.isPending) {
                setMessage("");
                mutation.mutate(draft.trim());
              }
            }}
          >
            <label htmlFor="case-note-input">Add investigation note</label>
            <textarea
              id="case-note-input"
              rows={4}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              disabled={mutation.isPending}
              maxLength={4000}
              required
              placeholder="Record the evidence reviewed and your conclusion…"
            />
            <div className="case-note-footer">
              <span className="case-small muted">
                {draft.length}/4,000 · Plain text · Visible to authorized users
              </span>
              <button
                className="button small"
                disabled={mutation.isPending || !draft.trim()}
              >
                {mutation.isPending ? "Saving note…" : "Save note"}
              </button>
            </div>
            {mutation.isError && (
              <>
                <ErrorState error={mutation.error} />
                <p className="case-small muted">
                  If the request timed out, check the refreshed notes before
                  resubmitting.
                </p>
              </>
            )}
            {message && (
              <p className="case-success" role="status">
                {message}
              </p>
            )}
          </form>
        )}
        <QueryState query={query}>
          {(data) => (
            <>
              {!data.items.length && (
                <EmptyState
                  title="No analyst notes yet"
                  description={
                    canWrite
                      ? "Add the first investigation observation above."
                      : "Analyst observations will appear here."
                  }
                />
              )}
              <ol className="case-notes">
                {data.items.map((note) => (
                  <li key={note.id}>
                    <div>
                      <strong>
                        {note.author?.username || "Former analyst"}
                      </strong>
                      {note.author && <Badge>{note.author.role}</Badge>}
                      <time dateTime={note.created_at}>
                        {utc(note.created_at)}
                      </time>
                    </div>
                    <p>{note.comment}</p>
                  </li>
                ))}
              </ol>
              <Pagination
                offset={offset}
                limit={20}
                total={data.total}
                onChange={setOffset}
              />
            </>
          )}
        </QueryState>
      </div>
    </Panel>
  );
}
