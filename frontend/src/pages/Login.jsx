import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import {
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  LoaderCircle,
  ShieldCheck,
  LockKeyhole,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { errorMessage } from "../services/api";

export default function Login({ registration = false }) {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [username, setUsername] = useState(location.state?.username || "");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const requested = location.state?.from;
  const destination =
    typeof requested === "string" &&
    requested.startsWith("/") &&
    !requested.startsWith("//") &&
    !["/login", "/register"].includes(requested)
      ? requested
      : "/";
  if (auth.user) return <Navigate to={destination} replace />;
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (registration) {
        await auth.registerAccount({
          username,
          email,
          full_name: fullName || null,
          password,
        });
        navigate("/login", {
          replace: true,
          state: { username, registered: true },
        });
      } else {
        await auth.signIn({ username, password });
      }
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  const waiting = busy || auth.status === "loading";
  return (
    <div className="auth-screen">
      <section className="auth-story">
        <Link to="/login" className="brand">
          <span className="brand-icon">
            <ShieldCheck size={27} strokeWidth={1.6} />
          </span>
          <span>
            CyberSentinel<small>SECURITY OPERATIONS</small>
          </span>
        </Link>
        <div className="auth-story-body">
          <div className="eyebrow">YOUR SECURITY WORKSPACE</div>
          <h1>
            Every investigation
            <br />
            starts with you.
          </h1>
          <p>
            A focused space for the people who protect.
            <br />
            Sign in to your CyberSentinel workspace.
          </p>
          <div className="auth-emblem" aria-hidden="true">
            <div>
              <Fingerprint size={90} strokeWidth={1} />
            </div>
            <span>IDENTITY · ACCESS · ACCOUNTABILITY</span>
          </div>
        </div>
        <div className="auth-story-footer">
          <ShieldCheck size={16} />
          Defensive security. Clear accountability.
        </div>
      </section>
      <section className="auth-form-area">
        <div className="auth-form-card">
          <div className="auth-lock">
            <LockKeyhole size={22} />
          </div>
          <div className="eyebrow">
            {registration ? "JOIN YOUR WORKSPACE" : "WORKSPACE ACCESS"}
          </div>
          <h2>{registration ? "Create an account" : "Welcome back"}</h2>
          <p className="auth-subtitle">
            {registration
              ? "New accounts start with read-only Viewer access."
              : "Enter your credentials to continue."}
          </p>
          {location.state?.registered && (
            <p className="auth-success" role="status">
              Account created. Sign in with your username.
            </p>
          )}
          {(error || auth.error) && (
            <div className="error-banner" role="alert">
              {error || auth.error}
              {auth.status === "error" && (
                <button
                  type="button"
                  className="auth-text-button"
                  onClick={auth.retrySession}
                >
                  Retry connection
                </button>
              )}
            </div>
          )}
          <form onSubmit={submit}>
            <label htmlFor="username">Username</label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              required
              minLength={3}
              maxLength={64}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Your username"
              disabled={waiting}
            />
            {registration && (
              <>
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  maxLength={254}
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                  disabled={waiting}
                />
                <label htmlFor="full-name">
                  Full name <span>(optional)</span>
                </label>
                <input
                  id="full-name"
                  autoComplete="name"
                  maxLength={150}
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  disabled={waiting}
                />
              </>
            )}
            <label htmlFor="password">Password</label>
            <div className="password-field">
              <input
                id="password"
                type={visible ? "text" : "password"}
                autoComplete={
                  registration ? "new-password" : "current-password"
                }
                required
                minLength={registration ? 12 : 1}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                disabled={waiting}
                aria-describedby={registration ? "password-help" : undefined}
              />
              <button
                type="button"
                aria-label={visible ? "Hide password" : "Show password"}
                onClick={() => setVisible(!visible)}
                disabled={waiting}
              >
                {visible ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>
            {registration && (
              <p id="password-help" className="field-help">
                Use at least 12 characters. Passphrases are welcome; maximum 72
                UTF-8 bytes.
              </p>
            )}
            <button type="submit" className="auth-submit" disabled={waiting}>
              {waiting ? (
                <>
                  <LoaderCircle size={17} className="spinning" />
                  {busy ? "Please wait…" : "Checking session…"}
                </>
              ) : (
                <>
                  {registration ? "Create account" : "Sign in"}
                  <ArrowRight size={17} />
                </>
              )}
            </button>
          </form>
          <p className="auth-switch">
            {registration
              ? "Already have an account?"
              : "Need workspace access?"}{" "}
            <Link to={registration ? "/login" : "/register"}>
              {registration ? "Sign in" : "Create an account"}
            </Link>
          </p>
          <div className="auth-form-note">
            <LockKeyhole size={14} />
            <span>Your access is governed by your assigned role.</span>
          </div>
        </div>
        <p className="auth-version">
          CyberSentinel · Local development workspace
        </p>
      </section>
    </div>
  );
}
