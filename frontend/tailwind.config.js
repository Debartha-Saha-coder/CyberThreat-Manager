/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0a0e1a',
          800: '#0d1224',
          700: '#111827',
          600: '#1a2035',
          500: '#1e2640',
        },
        cyber: {
          blue: '#3b82f6',
          cyan: '#06b6d4',
          purple: '#7c3aed',
          green: '#10b981',
          red: '#ef4444',
          orange: '#f97316',
          yellow: '#f59e0b',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'Segoe UI', 'system-ui', 'sans-serif'],
        display: ['Oswald', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
