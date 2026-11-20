import type { Config } from "tailwindcss";

export default {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        cyber: {
          dark: "#0b0f19",
          card: "#111827",
          border: "#1f2937",
          accent: "#06b6d4",
          neon: "#10b981",
          danger: "#ef4444",
          warning: "#f59e0b",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
