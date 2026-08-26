const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Indicator = { sev: "high" | "med" | "low"; text: string };
export type RelayHop = { host: string; ip: string | null; is_private: boolean };
export type CaseSummary = { case_id: string; created_at: string; subject: string | null; score: number; verdict: string };

export type AnalysisResult = {
  case_id: string;
  generated_at: string;
  verdict: string;
  score: number;
  nb_classifier: {
    probability_phishing: number;
    contributors: { token: string; weight: number }[];
    model: string;
    training_samples: number;
    vocabulary_size: number;
  };
  headers: {
    subject: string | null;
    from: string | null;
    reply_to: string | null;
    return_path: string | null;
    auth_results: string | null;
  };
  indicators: Indicator[];
  relay_hops: RelayHop[];
  target_ip: string | null;
  spf_live: { found: boolean | null; record?: string; mechanism_match?: boolean; error?: boolean } | null;
  geolocation: {
    simulated: boolean;
    ip: string;
    city: string;
    region: string;
    country: string;
    isp: string;
    timezone: string;
  } | null;
  threat_history_matches: string[];
};

export async function analyzeEmail(rawEmail: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_URL}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_email: rawEmail }),
  });
  if (!res.ok) throw new Error(`Analyze failed: ${res.status}`);
  return res.json();
}

export async function listCases(): Promise<CaseSummary[]> {
  const res = await fetch(`${API_URL}/api/cases`, { cache: "no-store" });
  if (!res.ok) return [];
  return res.json();
}

export async function clearCases(): Promise<void> {
  await fetch(`${API_URL}/api/cases`, { method: "DELETE" });
}
