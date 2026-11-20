import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ARTEX-Pro | Autonomous Cyber Recon & Exploit Control Center",
  description: "Enterprise Autonomous Multi-Agent Security Platform (Go Core + Next.js + PostgreSQL)",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#0b0f19] text-gray-100 antialiased">
        {children}
      </body>
    </html>
  );
}
