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
          50: "#f6f7f9",
          100: "#e9ecf1",
          200: "#ccd3df",
          300: "#a5b1c5",
          400: "#7383a0",
          500: "#54627f",
          600: "#3f4a62",
          700: "#2e3648",
          800: "#1f2433",
          900: "#141923"
        },
        signal: {
          good: "#15803d",
          warn: "#d97706",
          bad: "#b91c1c",
          info: "#0369a1"
        }
      },
      boxShadow: {
        panel: "0 8px 28px rgba(16, 24, 40, 0.14)"
      }
    }
  },
  plugins: []
};

export default config;
