import { useAuth } from "../context/AuthContext";
import { ranges, useDashboard } from "../context/DashboardContext";
import { Badge, PageHeading, Panel } from "../components/common/UI";
export default function Settings() {
  const { user } = useAuth();
  const { preferences, setPreferences } = useDashboard();
  return (
    <>
      <PageHeading
        title="Workspace settings"
        description="Your account and preferences for this browser."
      />
      <div className="equal-grid">
        <Panel
          title="Your profile"
          subtitle="Managed by your CyberSentinel administrator"
        >
          <dl className="profile-list">
            <div>
              <dt>Name</dt>
              <dd>{user.full_name || user.username}</dd>
            </div>
            <div>
              <dt>Username</dt>
              <dd>{user.username}</dd>
            </div>
            <div>
              <dt>Email</dt>
              <dd>{user.email}</dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd>
                <Badge>{user.role}</Badge>
              </dd>
            </div>
            <div>
              <dt>Account ID</dt>
              <dd className="mono">{user.id}</dd>
            </div>
          </dl>
        </Panel>
        <Panel
          title="Browser-local preferences"
          subtitle="Stored on this device for this account; no server configuration changes"
        >
          <div className="preferences-form">
            <label>
              Default dashboard range
              <select
                aria-label="Default dashboard range"
                value={preferences.defaultRange}
                onChange={(e) =>
                  setPreferences((p) => ({
                    ...p,
                    defaultRange: e.target.value,
                  }))
                }
              >
                {ranges.map((r) => (
                  <option key={r} value={r}>
                    {r.toUpperCase()}
                  </option>
                ))}
              </select>
              <small>Used on your next workspace visit.</small>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={preferences.autoRefresh}
                onChange={(e) =>
                  setPreferences((p) => ({
                    ...p,
                    autoRefresh: e.target.checked,
                  }))
                }
              />
              <span>
                Automatically refresh data
                <small>
                  Polling pauses in background tabs. Manual refresh remains
                  available.
                </small>
              </span>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={preferences.collapsed}
                onChange={(e) =>
                  setPreferences((p) => ({ ...p, collapsed: e.target.checked }))
                }
              />
              <span>
                Compact desktop sidebar
                <small>Mobile navigation uses a drawer.</small>
              </span>
            </label>
            <div className="preference-appearance">
              <span>Appearance</span>
              <Badge>Dark</Badge>
            </div>
          </div>
        </Panel>
      </div>
    </>
  );
}
