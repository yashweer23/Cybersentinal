import { lazy, Suspense } from "react";
import { LoadingSkeleton } from "./components/common/UI";
import { Link, Navigate, Outlet, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { DashboardProvider } from "./context/DashboardContext";
const Overview = lazy(() => import("./pages/Overview"));
const Incidents = lazy(() => import("./pages/Incidents"));
const IncidentInvestigation = lazy(
  () => import("./pages/IncidentInvestigation"),
);
const LiveEvents = lazy(() => import("./pages/LiveEvents"));
const ThreatIntelligence = lazy(() => import("./pages/ThreatIntelligence"));
const DetectionRules = lazy(() => import("./pages/DetectionRules"));
const Analytics = lazy(() => import("./pages/Analytics"));
const AIAnalyst = lazy(() => import("./pages/AIAnalyst"));
const SystemHealth = lazy(() => import("./pages/SystemHealth"));
const Settings = lazy(() => import("./pages/Settings"));
import Login from "./pages/Login";
const Admin = lazy(() => import("./pages/Admin"));
import ProtectedRoute from "./components/ProtectedRoute";
function Workspace() {
  return (
    <DashboardProvider>
      <Layout>
        <Suspense fallback={<LoadingSkeleton rows={6} />}>
          <Outlet />
        </Suspense>
      </Layout>
    </DashboardProvider>
  );
}
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login key="login" />} />
      <Route path="/register" element={<Login key="register" registration />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Workspace />}>
          <Route path="/" element={<Overview />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route
            path="/incidents/:incident_id"
            element={<IncidentInvestigation />}
          />
          <Route path="/events" element={<LiveEvents />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
          <Route path="/rules" element={<DetectionRules />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/ai-analyst" element={<AIAnalyst />} />
          <Route path="/health" element={<SystemHealth />} />
          <Route
            path="/system-health"
            element={<Navigate to="/health" replace />}
          />
          <Route path="/settings" element={<Settings />} />
          <Route element={<ProtectedRoute roles={["ADMIN"]} />}>
            <Route path="/admin" element={<Admin />} />
          </Route>
          <Route
            path="*"
            element={
              <section className="panel not-found">
                <h1>Page not found</h1>
                <p>This route does not exist.</p>
                <Link className="button secondary" to="/">
                  Return to overview
                </Link>
              </section>
            }
          />
        </Route>
      </Route>
    </Routes>
  );
}
