import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          50: "#E7ECFF",
          100: "#D2DAF5",
          200: "#A7B0D6",
          300: "#8E98C2",
          400: "#6C769E",
          500: "#4B567F",
          600: "#2F3A5D",
          700: "#1E2A44",
          800: "#101A2F",
          900: "#0B1020",
          950: "#070A12"
        },
        accent: {
          cyan: "#35D3FF",
          violet: "#8A5CFF"
        },
        signal: {
          good: "#27E0A3",
          warn: "#FFB020",
          bad: "#FF4D6D",
          info: "#35D3FF"
        }
      },
      boxShadow: {
        panel: "0 8px 28px rgba(0, 0, 0, 0.35)"
      }
    }
  },
  plugins: []
};

export default config;
