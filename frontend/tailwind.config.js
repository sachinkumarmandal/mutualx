/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        mint: { 50: '#f2fbf6', 100: '#e3f6ec', 200: '#c9ecd9', 300: '#a5dec0' },
        emerald: { 500: '#10b981', 600: '#059669', 700: '#047857' },
        navy: { 700: '#16294a', 800: '#0f1f3d', 900: '#0a1629' },
      },
      fontFamily: {
        sans: ['"Manrope Variable"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Instrument Serif"', 'ui-serif', 'Georgia', 'serif'],
      },
      boxShadow: {
        glass: '0 1px 0 rgba(255,255,255,.7) inset, 0 10px 30px -12px rgba(6,78,59,.25)',
      },
      keyframes: {
        rise: { from: { opacity: '0', transform: 'translateY(8px)' }, to: { opacity: '1', transform: 'none' } },
      },
      animation: { rise: 'rise .45s cubic-bezier(.2,.7,.2,1) both' },
    },
  },
  plugins: [],
};
