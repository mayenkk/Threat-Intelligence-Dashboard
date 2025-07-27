/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}",],
  theme: {
    extend: {
      colors: {
        'cyber-blue': '#00d4ff',
        'cyber-green': '#00ff88',
        'cyber-red': '#ff0040',
        'cyber-purple': '#8000ff',
        'dark-bg': '#0a0a0a',
        'dark-card': '#1a1a1a',
      },
    },
  },
  plugins: [],
}

