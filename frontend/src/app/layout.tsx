import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BaitBox — Disposable Detonation Chamber for Suspicious Links",
  description:
    "Vultr Agent Rush Hackathon — Track 01: Blast Radius Zero (Pattern B). Paste any suspicious link to detonate it inside a secret-free, isolated container on Vultr and receive a plain-language verdict backed by screenshots and containment proof.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#090d16] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}
