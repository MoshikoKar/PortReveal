import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiError, newRequestId } from '../api';
import { Card } from './ui';

interface State {
  error: Error | null;
  reference: string | null;
}

/** Last line of defence for render errors: a readable page with a reference id instead of a blank screen.
 *  The reference is the failing request's id for API errors (matches the backend log), otherwise a new id
 *  that is written to the browser console together with the stack. */
class Boundary extends Component<{ children: ReactNode; onHome: () => void }, State> {
  state: State = { error: null, reference: null };

  static getDerivedStateFromError(error: Error): State {
    const reference = error instanceof ApiError && error.requestId ? error.requestId : newRequestId();
    return { error, reference };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[nf] UI error, reference ${this.state.reference}:`, error, info.componentStack);
  }

  /** Leave the failing page without a full reload: route to the dashboard, then render children again. */
  goHome = () => {
    this.props.onHome();
    this.setState({ error: null, reference: null });
  };

  render() {
    const { error, reference } = this.state;
    if (!error) return this.props.children;
    return (
      <div style={{ maxWidth: 640, margin: '48px auto', padding: '0 16px' }}>
        <Card title="Something went wrong">
          <p>This page failed to display. Reloading usually fixes it; if it keeps happening, report the reference below.</p>
          <div className="alert error" style={{ margin: '12px 0' }}>{error.message || 'Unexpected error'}</div>
          <p className="small muted">Reference: <span className="mono">{reference}</span></p>
          <div className="row">
            <button className="btn primary" onClick={() => window.location.reload()}>Reload</button>
            <button className="btn" onClick={this.goHome}>Go to dashboard</button>
          </div>
        </Card>
      </div>
    );
  }
}

/** Must render inside the router: "Go to dashboard" navigates in-app instead of reloading. */
export function ErrorBoundary({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  return <Boundary onHome={() => navigate('/')}>{children}</Boundary>;
}
