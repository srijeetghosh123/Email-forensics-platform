/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: "#EDE6D3",
        paperdark: "#E0D7BE",
        card: "#F7F3E8",
        ink: "#1B2A4A",
        inksoft: "#3C4A66",
        alert: "#A8281E",
        alertbg: "#F3DEDA",
        warn: "#9C6B14",
        warnbg: "#F2E6C8",
        safe: "#2F6F63",
        safebg: "#DCEAE4",
      },
      fontFamily: {
        mono: ["'IBM Plex Mono'", "monospace"],
        sans: ["'IBM Plex Sans'", "sans-serif"],
        stamp: ["'Special Elite'", "cursive"],
      },
    },
  },
  plugins: [],
};
