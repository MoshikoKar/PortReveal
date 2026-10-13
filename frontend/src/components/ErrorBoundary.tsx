import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ApiError, newRequestId } from '../api';
import { Card } from './ui';

interface State {
  error: Error | null;
  reference: string | null;
}

/** Last line of defence for render errors: a readable page with a reference id instead of a blank screen.
 *  The reference is the failing request's id for API errors (matches the backend log), otherwise a new id
 *  that is written to the browser console together with the stack. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null, reference: null };

  static getDerivedStateFromError(error: Error): State {
    const reference = error instanceof ApiError && error.requestId ? error.requestId : newRequestId();
    return { error, reference };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[nf] UI error, reference ${this.state.reference}:`, error, info.componentStack);
  }

  render() {
    const { error, reference } = this.state;
    if (!error) return this.props.children;
    return (
      <div style={{ maxWidth: 640, margin: '48px auto', padding: '0 16px' }}>
        <Card title="Something went wrong">
          <p>This page failed to display. Reloading usually fixes it; if it keeps happening, report the reference below.</p>
          <div className="alert error" style={{ margin: '12px 0' }}>{error.message || 'Unexpected error'}</div>
          <p className="small muted">Reference: <span className="mono">{reference}</span></p>
          <button className="btn primary" onClick={() => window.location.reload()}>Reload</button>
        </Card>
      </div>
    );
  }
}
