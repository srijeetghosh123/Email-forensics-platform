import { RelayHop } from "@/lib/api";

export default function RelayPath({ hops }: { hops: RelayHop[] }) {
  if (!hops.length) {
    return <span className="font-mono text-xs text-inksoft">No Received headers found to reconstruct a relay path.</span>;
  }
  return (
    <div className="flex flex-wrap items-center">
      {hops.map((h, idx) => {
        const isOrigin = idx === 0 && !h.is_private;
        return (
          <div key={idx} className="flex items-center">
            <div
              className={`font-mono text-[11px] border rounded-md px-2.5 py-2 min-w-[150px] max-w-[220px] ${
                isOrigin
                  ? "border-alert bg-alertbg"
                  : h.is_private
                  ? "border-ink/20 bg-[#fffdf7] opacity-60"
                  : "border-ink/20 bg-[#fffdf7]"
              }`}
            >
              <span className="block text-[9px] uppercase tracking-wider text-inksoft mb-0.5">
                {idx === 0 ? "origin hop" : `hop ${idx + 1}`}
              </span>
              {h.host}
              {h.ip && (
                <>
                  <br />
                  {h.ip}
                </>
              )}
            </div>
            {idx < hops.length - 1 && <span className="font-mono text-inksoft px-2">&rarr;</span>}
          </div>
        );
      })}
    </div>
  );
}
