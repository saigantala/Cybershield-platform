/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        soc: {
          main: "#080D18",
          sidebar: "#0B1220",
          surface: "#111C2D",
          elevated: "#162338",
          hover: "#1E2F4A",
          border: "rgba(59, 130, 246, 0.15)",
          glass: "rgba(17, 28, 45, 0.75)",
        },
        primary: {
          DEFAULT: "#3B82F6",
          foreground: "#FFFFFF",
          glow: "rgba(59, 130, 246, 0.35)",
        },
        accent: {
          cyan: "#22D3EE",
          purple: "#8B5CF6",
          glow: "rgba(34, 211, 238, 0.3)",
        },
        severity: {
          critical: "#FB7185",
          high: "#F59E0B",
          medium: "#38BDF8",
          low: "#34D399",
          info: "#94A3B8",
        },
      },
      borderRadius: {
        lg: "0.625rem",
        md: "0.5rem",
        sm: "0.375rem",
      },
      boxShadow: {
        glass: "0 8px 32px 0 rgba(0, 0, 0, 0.37)",
        "blue-glow": "0 0 20px -3px rgba(59, 130, 246, 0.3)",
        "cyan-glow": "0 0 20px -3px rgba(34, 211, 238, 0.3)",
        "critical-glow": "0 0 20px -3px rgba(251, 113, 133, 0.35)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: 0 },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: 0 },
        },
        pulseGlow: {
          "0%, 100%": { opacity: 0.8, transform: "scale(1)" },
          "50%": { opacity: 1, transform: "scale(1.03)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "pulse-glow": "pulseGlow 3s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
