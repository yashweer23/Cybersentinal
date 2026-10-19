import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowLeftToLine,
  ArrowRightFromLine,
  Bot,
  ChartNoAxesCombined,
  CircleHelp,
  Clock3,
  Crosshair,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  RefreshCw,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  X,
} from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { useIsFetching } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext";
import { ranges, useDashboard } from "../context/DashboardContext";
import { errorMessage } from "../services/api";
import { Badge } from "./common/UI";
const navigation = [
  ["/", "Overview", LayoutDashboard],
  ["/incidents", "Incidents", Crosshair],
  ["/events", "Live Events", Activity],
  ["/threat-intelligence", "Threat Intelligence", Globe2],
  ["/analytics", "Analytics", ChartNoAxesCombined],
  ["/ai-analyst", "AI Analyst", Bot],
  ["/rules", "Detection Rules", SlidersHorizontal],
  ["/health", "System Health", Radar],
  ["/settings", "Settings", Settings2],
];
export default function Layout({ children }) {
  const auth = useAuth();
  const { range, setRange, preferences, setPreferences, refresh } =
    useDashboard();
  const location = useLocation();
  const fetching = useIsFetching();
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [error, setError] = useState(null);
  const drawer = useRef(null),
    menu = useRef(null);
  const nav =
    auth.user.role === "ADMIN"
      ? [...navigation, ["/admin", "User Access", Users]]
      : navigation;
  const title =
    nav.find(([path]) => path === location.pathname)?.[1] ||
    (location.pathname.startsWith("/incidents/")
      ? "Incident Investigation"
      : "Workspace");
  const ranged = ["/", "/rules", "/threat-intelligence"].includes(
    location.pathname,
  );
  useEffect(() => {
    setOpen(false);
    document.title = `${title} · CyberSentinel`;
  }, [location.pathname, title]);
  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawer.current?.querySelector("button")?.focus();
    const keydown = (event) => {
      if (event.key === "Escape") {
        setOpen(false);
        menu.current?.focus();
      }
      if (event.key === "Tab") {
        const focusable = [
          ...drawer.current.querySelectorAll("a,button"),
        ].filter((e) => e.getClientRects().length);
        const first = focusable[0],
          last = focusable.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", keydown);
    };
  }, [open]);
  async function logout() {
    setSigningOut(true);
    setError(null);
    try {
      await auth.signOut();
    } catch (failure) {
      setError(errorMessage(failure, "Sign out failed. Please retry."));
    } finally {
      setSigningOut(false);
    }
  }
  return (
    <div
      className={`app-shell soc-shell ${preferences.collapsed ? "is-collapsed" : ""} ${open ? "drawer-open" : ""}`}
    >
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      {open && (
        <button
          className="drawer-backdrop"
          aria-label="Close navigation"
          onClick={() => {
            setOpen(false);
            menu.current?.focus();
          }}
        />
      )}
      <aside
        className="sidebar"
        ref={drawer}
        aria-label="Workspace navigation"
        role={open ? "dialog" : undefined}
        aria-modal={open ? "true" : undefined}
      >
        <div className="sidebar-brand">
          <NavLink to="/" className="brand" aria-label="CyberSentinel overview">
            <span className="brand-icon">
              <ShieldCheck size={29} />
            </span>
            <span className="nav-text">
              CyberSentinel<small>SECURITY OPERATIONS</small>
            </span>
          </NavLink>
          <button
            className="icon-button mobile-only drawer-close"
            aria-label="Close navigation"
            onClick={() => {
              setOpen(false);
              menu.current?.focus();
            }}
          >
            <X size={20} />
          </button>
        </div>
        <div className="workspace-tag nav-text">
          <span className="workspace-monogram">CS</span>
          <div>
            Analyst workspace<small>Defensive security platform</small>
          </div>
        </div>
        <div className="nav-section nav-text">WORKSPACE</div>
        <nav>
          {nav.map(([path, name, Icon]) => (
            <NavLink
              key={path}
              to={path}
              end={path === "/"}
              title={preferences.collapsed ? name : undefined}
              className={({ isActive }) =>
                `nav-link ${isActive ? "active" : ""}`
              }
            >
              <Icon size={18} />
              <span className="nav-text">{name}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <a
            className="nav-link"
            href="/docs"
            target="_blank"
            rel="noreferrer"
            title="API documentation"
          >
            <CircleHelp size={18} />
            <span className="nav-text">API documentation</span>
          </a>
          <button
            className="nav-link collapse-control"
            aria-label={
              preferences.collapsed ? "Expand sidebar" : "Collapse sidebar"
            }
            onClick={() =>
              setPreferences((p) => ({ ...p, collapsed: !p.collapsed }))
            }
          >
            {preferences.collapsed ? (
              <ArrowRightFromLine size={18} />
            ) : (
              <ArrowLeftToLine size={18} />
            )}
            <span className="nav-text">Collapse sidebar</span>
          </button>
          <div className="sidebar-edition nav-text">
            <span>CYBERSENTINEL</span>
            <small>v0.15 · SOC workspace</small>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="header-title">
            <button
              ref={menu}
              className="icon-button mobile-only"
              aria-label="Open navigation"
              aria-expanded={open}
              onClick={() => setOpen(true)}
            >
              <Menu size={20} />
            </button>
            <span className="header-product">WORKSPACE</span>
            <span className="header-slash">/</span>
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            {ranged && (
              <label className="range-selector">
                <Clock3 size={14} />
                <span className="sr-only">Time range</span>
                <select
                  aria-label="Time range"
                  value={range}
                  onChange={(e) => setRange(e.target.value)}
                >
                  {ranges.map((r) => (
                    <option key={r} value={r}>
                      Last {r.toUpperCase()}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button
              className="icon-button refresh-control"
              aria-label="Refresh data"
              title="Refresh visible data"
              onClick={refresh}
              disabled={fetching > 0}
            >
              <RefreshCw size={16} className={fetching ? "spinning" : ""} />
            </button>
            <div className="user-separator" />
            <div className="user-avatar" aria-hidden="true">
              {auth.user.username.slice(0, 2).toUpperCase()}
            </div>
            <div className="header-user">
              <strong>{auth.user.full_name || auth.user.username}</strong>
              <span>{auth.user.role}</span>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              title="Sign out"
              disabled={signingOut}
              onClick={logout}
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          {(error || auth.error) && (
            <div className="error-banner" role="alert">
              {error || auth.error}
            </div>
          )}
          {children}
        </main>
        <footer>
          <span>
            <ShieldCheck size={13} />
            CyberSentinel · Defensive security analytics
          </span>
          <span>
            All timestamps UTC <Badge>SOC workspace</Badge>
          </span>
        </footer>
      </div>
    </div>
  );
}
