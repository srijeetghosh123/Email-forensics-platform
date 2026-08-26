import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "CASE 26106 — Email Threat & Forensic Intelligence",
  description: "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="text-ink font-sans min-h-screen p-4 md:p-6">{children}</body>
    </html>
  );
}
