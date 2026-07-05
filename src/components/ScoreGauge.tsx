export default function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-signal' : score >= 50 ? 'text-warn' : 'text-crit';
  const ring = score >= 80 ? 'stroke-signal' : score >= 50 ? 'stroke-warn' : 'stroke-crit';
  const label = score >= 80 ? 'Solid baseline' : score >= 50 ? 'Needs attention' : 'High risk';

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex items-center gap-5">
      <div className="relative w-32 h-32 shrink-0">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#1F2A24" strokeWidth="10" />
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            className={ring}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono text-3xl font-medium ${color}`}>{score}</span>
          <span className="text-[10px] text-muted font-mono">/ 100</span>
        </div>
      </div>
      <div>
        <p className={`font-mono text-sm tracking-wide ${color}`}>{label}</p>
        <p className="text-xs text-muted mt-1 max-w-[16rem]">
          A general signal based on the checks below — not a complete audit.
        </p>
      </div>
    </div>
  );
}
