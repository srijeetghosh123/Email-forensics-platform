import { AnalysisResult, CaseSummary } from "@/lib/api";

export function HeaderTable({ headers }: { headers: AnalysisResult["headers"] }) {
  const rows: [string, string | null][] = [
    ["Subject", headers.subject],
    ["From", headers.from],
    ["Reply-To", headers.reply_to || "— (not set)"],
    ["Return-Path", headers.return_path],
    ["Authentication", headers.auth_results || "— (no Authentication-Results header)"],
  ];
  return (
    <table className="w-full border-collapse text-[12.5px]">
      <tbody>
        {rows.map(([label, value]) => (
          <tr key={label} className="border-b border-ink/15">
            <th className="text-left align-top py-1.5 px-2 font-mono text-[10.5px] uppercase tracking-wider text-inksoft w-[150px]">
              {label}
            </th>
            <td className="text-left align-top py-1.5 px-2 font-mono">{value || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function IndicatorList({ indicators }: { indicators: AnalysisResult["indicators"] }) {
  const dotColor = { high: "bg-alert", med: "bg-warn", low: "bg-safe" };
  if (!indicators.length) return <p className="text-sm">No indicators triggered.</p>;
  return (
    <ul className="list-none p-0 m-0">
      {indicators.map((i, idx) => (
        <li key={idx} className="flex gap-2.5 py-2 border-b border-dotted border-ink/15 text-[13px] last:border-none">
          <span className={`w-2 h-2 rounded-full mt-1.5 flex-none ${dotColor[i.sev]}`} />
          <span>{i.text}</span>
        </li>
      ))}
    </ul>
  );
}

export function GeoCard({ geo, targetIp }: { geo: AnalysisResult["geolocation"]; targetIp: string | null }) {
  if (!targetIp) {
    return <p className="font-mono text-xs text-inksoft">No public IP address found in the header chain to geolocate.</p>;
  }
  if (!geo) {
    return <p className="font-mono text-xs text-inksoft">Resolving origin for {targetIp}…</p>;
  }
  const fields: [string, string | number][] = [
    ["IP Address", geo.ip],
    ["City", geo.city],
    ["Region", geo.region],
    ["Country", geo.country],
    ["Network / ISP", geo.isp],
    ["Timezone", geo.timezone],
  ];
  return (
    <div>
      <div className="grid grid-cols-2 gap-x-5 gap-y-2 font-mono text-[12.5px] bg-[#fffdf7] border border-ink/20 rounded-lg p-4">
        {fields.map(([label, value]) => (
          <div key={label}>
            <span className="block text-[10px] uppercase tracking-wider text-inksoft mb-0.5">{label}</span>
            {value}
          </div>
        ))}
      </div>
      {geo.simulated && (
        <span className="inline-block mt-2 font-mono text-[10px] bg-warnbg text-warn px-2 py-1 rounded">
          LIVE LOOKUP UNAVAILABLE — showing offline reference data for demo continuity
        </span>
      )}
    </div>
  );
}

export function SPFCard({ spf, domain }: { spf: AnalysisResult["spf_live"]; domain: string | null }) {
  if (!spf || spf.found === null) {
    return <p className="font-mono text-xs text-inksoft mt-2">Live SPF lookup unavailable or not applicable.</p>;
  }
  return (
    <div className="font-mono text-xs mt-2 bg-[#fffdf7] border border-ink/20 rounded-lg p-3">
      {spf.found ? (
        <>
          SPF record found for {domain}. Origin IP mechanism match:{" "}
          <b className={spf.mechanism_match ? "text-safe" : "text-alert"}>{spf.mechanism_match ? "YES" : "NO"}</b>
        </>
      ) : (
        <>No SPF record published for {domain}.</>
      )}
    </div>
  );
}

export function CaseLog({ cases }: { cases: CaseSummary[] }) {
  if (!cases.length) {
    return <span className="font-mono text-[11.5px] text-inksoft">No prior cases logged yet.</span>;
  }
  return (
    <table className="w-full border-collapse text-xs">
      <thead>
        <tr className="border-b border-ink/15">
          <th className="text-left font-mono uppercase tracking-wider text-inksoft py-1.5 px-2">Case ID</th>
          <th className="text-left font-mono uppercase tracking-wider text-inksoft py-1.5 px-2">When</th>
          <th className="text-left font-mono uppercase tracking-wider text-inksoft py-1.5 px-2">Subject</th>
          <th className="text-left font-mono uppercase tracking-wider text-inksoft py-1.5 px-2">Score</th>
          <th className="text-left font-mono uppercase tracking-wider text-inksoft py-1.5 px-2">Verdict</th>
        </tr>
      </thead>
      <tbody>
        {cases.map((c) => (
          <tr key={c.case_id} className="border-b border-ink/15">
            <td className="font-mono py-1.5 px-2">{c.case_id}</td>
            <td className="font-mono py-1.5 px-2">{new Date(c.created_at).toLocaleString()}</td>
            <td className="py-1.5 px-2">{c.subject || "—"}</td>
            <td className="font-mono py-1.5 px-2">{c.score}/100</td>
            <td className="py-1.5 px-2">{c.verdict}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
