import { useEffect, useState } from "react";
import { Users, RefreshCw } from "lucide-react";
import { api, errorMessage } from "../services/api";
import { useAuth } from "../context/AuthContext";

export default function Admin() {
  const auth = useAuth();
  const [page, setPage] = useState({ items: [], total: 0 });
  const [offset, setOffset] = useState(0);
  const [version, setVersion] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .get("/users", {
        params: { limit: 20, offset },
        signal: controller.signal,
      })
      .then(({ data }) => setPage(data))
      .catch((failure) => {
        if (!controller.signal.aborted) setError(errorMessage(failure));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [offset, version]);
  async function change(user, action, value) {
    setBusy(user.id);
    setError(null);
    setNotice(null);
    try {
      const { data } = await api.patch(`/users/${user.id}/${action}`, value);
      setPage((current) => ({
        ...current,
        items: current.items.map((item) => (item.id === data.id ? data : item)),
      }));
      setNotice(`Updated ${data.username}.`);
      if (user.id === auth.user.id) await auth.refreshProfile();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(null);
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">ADMINISTRATION</div>
          <h1>User access</h1>
          <p>Manage workspace roles and account availability.</p>
        </div>
        <button
          className="button secondary"
          disabled={loading || Boolean(busy)}
          onClick={() => setVersion(version + 1)}
        >
          <RefreshCw size={15} />
          Refresh users
        </button>
      </div>
      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <p className="auth-success" role="status">
          {notice}
        </p>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Workspace members</h2>
            <p>At least one active administrator must remain.</p>
          </div>
          <Users size={20} className="muted" />
        </div>
        {loading ? (
          <p className="table-message" role="status">
            Loading members…
          </p>
        ) : (
          <div className="users-table-scroll">
            <table className="users-table">
              <thead>
                <tr>
                  <th scope="col">User</th>
                  <th scope="col">Role</th>
                  <th scope="col">Status</th>
                  <th scope="col">Account access</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <strong>
                        {user.username}
                        {user.id === auth.user.id ? " (you)" : ""}
                      </strong>
                      <small>{user.email}</small>
                    </td>
                    <td>
                      <select
                        aria-label={`Role for ${user.username}`}
                        value={user.role}
                        disabled={Boolean(busy)}
                        onChange={(event) =>
                          change(user, "role", { role: event.target.value })
                        }
                      >
                        {["ADMIN", "ANALYST", "VIEWER"].map((role) => (
                          <option key={role}>{role}</option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <span className={user.is_active ? "green-text" : "muted"}>
                        {user.is_active ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td>
                      <button
                        className="button secondary"
                        disabled={Boolean(busy)}
                        onClick={() =>
                          change(user, "status", { is_active: !user.is_active })
                        }
                      >
                        {busy === user.id
                          ? "Saving…"
                          : user.is_active
                            ? "Deactivate"
                            : "Activate"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!page.items.length && (
              <p className="table-message">No users found.</p>
            )}
          </div>
        )}
        <div className="panel-footer">
          <span>
            {page.total} members · {page.items.length ? offset + 1 : 0}–
            {offset + page.items.length} shown
          </span>
          <div className="pagination">
            <button
              className="button secondary"
              disabled={offset === 0 || loading || Boolean(busy)}
              onClick={() => setOffset(Math.max(0, offset - 20))}
            >
              Previous
            </button>
            <button
              className="button secondary"
              disabled={offset + 20 >= page.total || loading || Boolean(busy)}
              onClick={() => setOffset(offset + 20)}
            >
              Next
            </button>
          </div>
        </div>
      </section>
      <p className="info-note">
        Viewers read workspace data. Analysts investigate security activity.
        Administrators also manage user access. Changes are recorded in the
        audit log.
      </p>
    </>
  );
}
