import type { Config } from "tailwindcss";

const withAlpha = (variableName: string) => `rgb(var(${variableName}) / <alpha-value>)`;

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
    "./hooks/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: withAlpha("--bg-canvas"),
        surface: withAlpha("--bg-surface"),
        elevated: withAlpha("--bg-elevated"),
        inset: withAlpha("--bg-inset"),
        "border-subtle": withAlpha("--border-subtle"),
        "border-strong": withAlpha("--border-strong"),
        ink: {
          primary: withAlpha("--text-primary"),
          secondary: withAlpha("--text-secondary"),
          muted: withAlpha("--text-muted"),
        },
        sentinel: {
          primary: withAlpha("--accent-primary"),
          success: withAlpha("--accent-success"),
          warning: withAlpha("--accent-warning"),
          danger: withAlpha("--accent-danger"),
          ai: withAlpha("--accent-ai"),
          onAccent: withAlpha("--on-accent"),
        },
        syntax: {
          keyword: withAlpha("--syntax-keyword"),
          string: withAlpha("--syntax-string"),
          number: withAlpha("--syntax-number"),
          comment: withAlpha("--syntax-comment"),
          fn: withAlpha("--syntax-fn"),
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
