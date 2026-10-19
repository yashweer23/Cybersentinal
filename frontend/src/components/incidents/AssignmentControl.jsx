import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../../context/AuthContext";
import { useIncidentMutation } from "../../hooks/useIncident";
import { assignIncident, eligibleAnalysts } from "../../services/incidentsApi";
import { ErrorState, Pagination, QueryState } from "../common/UI";
import Dialog from "./Dialog";

export default function AssignmentControl({ incident, close, notify }) {
  const { user } = useAuth();
  const [selected, setSelected] = useState(incident.assigned_analyst_id || ""),
    [draft, setDraft] = useState(""),
    [search, setSearch] = useState(""),
    [offset, setOffset] = useState(0);
  const params = { limit: 10, offset, ...(search ? { q: search } : {}) };
  const query = useQuery({
    queryKey: ["eligible-analysts", params],
    queryFn: ({ signal }) => eligibleAnalysts(params, signal),
  });
  const mutation = useIncidentMutation(
    incident.incident_id,
    "assign",
    (id) => assignIncident(incident.incident_id, id || null),
    () => {
      notify("Assignment saved.");
      close();
    },
  );
  return (
    <Dialog title="Assign incident" onClose={close} busy={mutation.isPending}>
      <p>
        Current owner:{" "}
        <strong>{incident.assigned_analyst?.username || "Unassigned"}</strong>.
        Only active analysts and administrators are eligible.
      </p>
      <form
        className="case-search"
        onSubmit={(e) => {
          e.preventDefault();
          setSearch(draft.trim());
          setOffset(0);
        }}
      >
        <label>
          Find analyst
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            maxLength={100}
          />
        </label>
        <button className="button secondary small">Search</button>
      </form>
      <fieldset className="case-assignees" disabled={mutation.isPending}>
        <legend>Assignment</legend>
        <label>
          <input
            type="radio"
            name="assignee"
            checked={selected === ""}
            onChange={() => setSelected("")}
          />
          Unassigned
        </label>
        <QueryState query={query}>
          {(data) => (
            <>
              {data.items.map((person) => (
                <label key={person.id}>
                  <input
                    type="radio"
                    name="assignee"
                    checked={selected === person.id}
                    onChange={() => setSelected(person.id)}
                  />
                  <span>
                    <strong>{person.username}</strong>
                    <small>
                      {person.full_name || person.username} · {person.role}
                    </small>
                  </span>
                </label>
              ))}
              <Pagination
                offset={offset}
                limit={10}
                total={data.total}
                onChange={setOffset}
              />
            </>
          )}
        </QueryState>
      </fieldset>
      <p className="case-small muted">
        {selected ? `Selected ID: ${selected}` : "Selected: Unassigned"}
      </p>
      {mutation.isError && <ErrorState error={mutation.error} />}
      <div className="case-dialog-actions">
        <button
          className="button secondary"
          disabled={mutation.isPending}
          onClick={close}
        >
          Cancel
        </button>
        <button
          className="button secondary"
          disabled={
            mutation.isPending || incident.assigned_analyst_id === user.id
          }
          onClick={() => mutation.mutate(user.id)}
        >
          Assign to me
        </button>
        <button
          className="button"
          disabled={
            mutation.isPending ||
            (selected || null) === incident.assigned_analyst_id
          }
          onClick={() => mutation.mutate(selected)}
        >
          {mutation.isPending ? "Saving…" : "Save assignment"}
        </button>
      </div>
    </Dialog>
  );
}
