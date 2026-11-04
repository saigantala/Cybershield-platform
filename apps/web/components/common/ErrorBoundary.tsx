"use client";

import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[CYBERSHIELD ERROR BOUNDARY CAUGHT]", error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
    this.props.onReset?.();
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex min-h-[300px] w-full flex-col items-center justify-center rounded-xl border border-rose-500/30 bg-rose-950/20 p-8 text-center backdrop-blur-md">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-950/40 text-rose-400">
            <AlertTriangle className="h-6 w-6" />
          </div>
          <h3 className="mt-4 text-lg font-bold text-white">Component Error Intercepted</h3>
          <p className="mt-2 max-w-md text-xs leading-relaxed text-slate-400">
            An isolated client rendering exception occurred in this analytical module.
            Other SOC operations and monitoring feeds remain active.
          </p>
          {this.state.error && (
            <code className="mt-3 rounded border border-rose-500/20 bg-black/50 px-3 py-1 font-mono text-[11px] text-rose-300">
              {this.state.error.message || "Unknown error"}
            </code>
          )}
          <button
            onClick={this.handleReset}
            className="mt-5 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Reload Module
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
