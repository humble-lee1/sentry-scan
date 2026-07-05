export default function MonitorForm({ domain }: { domain: string }) {
  return (
    <div className="mt-12 border border-line rounded-md p-6 bg-panel text-center">
      <p className="font-mono text-sm text-signal mb-2">Monthly monitoring</p>
      <p className="text-sm text-muted mb-1">
        Get re-scanned automatically and alerted by email when something changes for{' '}
        <span className="text-paper">{domain}</span>.
      </p>
      <p className="text-xs text-muted mt-3 font-mono">
        <span className="border border-line px-2 py-1 rounded text-signalDim">Coming soon</span>
      </p>
    </div>
  );
}
