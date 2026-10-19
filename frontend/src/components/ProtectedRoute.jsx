import { Link, Navigate, Outlet, useLocation } from "react-router-dom";
import { LoaderCircle, ShieldX } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ roles }) {
  const auth = useAuth();
  const location = useLocation();
  if (auth.status === "loading")
    return (
      <div className="auth-loading" role="status">
        <LoaderCircle className="spinning" />
        Checking your session…
      </div>
    );
  if (auth.status === "error")
    return (
      <div className="auth-loading">
        <p role="alert">{auth.error}</p>
        <button className="button secondary" onClick={auth.retrySession}>
          Retry connection
        </button>
        <Link to="/login">Go to sign in</Link>
      </div>
    );
  if (!auth.user)
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  if (roles && !roles.includes(auth.user.role))
    return (
      <section className="panel forbidden-panel">
        <ShieldX size={40} />
        <div className="eyebrow">403 · ACCESS RESTRICTED</div>
        <h1>Administrator access required.</h1>
        <p>
          You are signed in as {auth.user.username} with the {auth.user.role}{" "}
          role. Ask an administrator if your responsibilities require different
          access.
        </p>
        <Link className="button secondary" to="/">
          Return to overview
        </Link>
      </section>
    );
  return <Outlet />;
}
