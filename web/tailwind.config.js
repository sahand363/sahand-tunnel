/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: "#111827",
        background: "#090d16",
        accent: "#38bdf8"
      }
    }
  },
  plugins: []
};
