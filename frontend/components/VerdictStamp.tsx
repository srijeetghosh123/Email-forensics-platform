export default function VerdictStamp({ verdict, score }: { verdict: string | null; score: number | null }) {
  if (verdict === null) {
    return (
      <div className="border border-dashed border-ink/20 rounded-lg min-h-[220px] flex items-center justify-center text-center p-5">
        <span className="font-mono text-xs text-inksoft">
          No evidence analyzed yet.
          <br />
          Load the sample case or paste a raw email to begin.
        </span>
      </div>
    );
  }

  const colorClass =
    verdict === "PHISHING DETECTED" ? "text-alert" : verdict === "SUSPICIOUS" ? "text-warn" : "text-safe";

  return (
    <div className="border border-dashed border-ink/20 rounded-lg min-h-[220px] flex flex-col items-center justify-center text-center p-5">
      <span
        className={`stamp-text text-3xl border-4 border-double px-6 py-2 -rotate-6 inline-block ${colorClass}`}
      >
        {verdict}
      </span>
      <div className="font-mono text-xs text-inksoft mt-4">Composite Risk Score</div>
      <div className="font-mono text-4xl font-bold">
        {score}
        <span className="text-base text-inksoft">/100</span>
      </div>
    </div>
  );
}
