import { AnalysisResult } from "@/lib/api";

export default function NBCard({ nb }: { nb: AnalysisResult["nb_classifier"] }) {
  const pct = Math.round(nb.probability_phishing * 100);
  return (
    <div className="bg-[#fffdf7] border border-ink/20 rounded-lg p-4">
      <div className="flex justify-between items-baseline">
        <span className="font-mono text-[10.5px] uppercase tracking-wider text-inksoft">
          P(phishing | message text)
        </span>
        <span className="font-mono text-xl font-bold">{pct}%</span>
      </div>
      <div className="bg-paperdark rounded-full h-3.5 overflow-hidden my-2">
        <div
          className="h-full bg-gradient-to-r from-safe via-warn to-alert"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="font-mono text-[10.5px] uppercase tracking-wider text-inksoft block mb-1">
        Top contributing tokens (log-odds weight)
      </span>
      <div className="flex flex-wrap gap-1.5">
        {nb.contributors.length === 0 && (
          <span className="font-mono text-xs text-inksoft">No modeled tokens found in this message.</span>
        )}
        {nb.contributors.map((c) => (
          <span
            key={c.token}
            className={`font-mono text-[11px] px-2 py-0.5 rounded ${
              c.weight > 0 ? "bg-alertbg text-alert" : "bg-safebg text-safe"
            }`}
          >
            {c.token} {c.weight > 0 ? "+" : ""}
            {c.weight.toFixed(2)}
          </span>
        ))}
      </div>
      <div className="font-mono text-[10px] text-inksoft mt-3 pt-2 border-t border-ink/10">
        {nb.model} · trained on {nb.training_samples} samples · vocab size {nb.vocabulary_size}
      </div>
    </div>
  );
}
