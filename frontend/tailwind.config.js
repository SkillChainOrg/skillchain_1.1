/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        terracotta: "#C65D3B",
        saffron: "#F4C430",
        forest: "#2F6B57",
        "warm-gray": "#9CA3AF",
        "deep-ink": "#0B0B0B",
        ivory: "#F9F6F1",
        parchment: "#F5EBDD",
        sandstone: "#D6CFC7",
        clay: "#A0522D",
        gold: "#D4AF37",
        "indigo-deep": "#1E1B4B",
      },
      fontFamily: {
        serif: ["Playfair Display", "serif"],
        sans: ["Inter", "sans-serif"],
      },
      backgroundImage: {
        "parchment-texture":
          "url('https://www.transparenttextures.com/patterns/paper-fibers.png')",
      },
    },
  },
  plugins: [],
};
