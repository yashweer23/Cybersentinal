import { Component } from "react";

// Do not render exception text or send component state/credentials to a remote logger.
export default class ErrorBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (this.state.failed) {
      return (
        <main className="app-recovery" role="alert">
          <div className="soc-panel">
            <h1>Something went wrong</h1>
            <p>The workspace could not be displayed. Reload to try again.</p>
            <div className="heading-actions">
              <button
                className="button primary"
                onClick={() => window.location.reload()}
              >
                Retry
              </button>
              <a className="button secondary" href="/">
                Return to Overview
              </a>
            </div>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
