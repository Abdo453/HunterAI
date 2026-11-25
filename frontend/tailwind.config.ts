import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "var(--bg-canvas)",
        surface: "var(--bg-surface)",
        elevated: "var(--bg-elevated)",
        inset: "var(--bg-inset)",
        "border-subtle": "var(--border-subtle)",
        "border-strong": "var(--border-strong)",
        ink: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        sentinel: {
          primary: "var(--accent-primary)",
          success: "var(--accent-success)",
          warning: "var(--accent-warning)",
          danger: "var(--accent-danger)",
          ai: "var(--accent-ai)",
          onAccent: "var(--on-accent)",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
      },
      boxShadow: {
        sentinelSm: "var(--shadow-sm)",
        sentinelMd: "var(--shadow-md)",
      },
    },
  },
  plugins: [],
};

export default config;
