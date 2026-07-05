/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Terminal/SOC-console inspired palette — dark, scan-line aesthetic
        ink: '#0B0F0E',        // near-black base, slightly green-tinted
        panel: '#111714',      // raised panel surface
        line: '#1F2A24',       // hairline borders
        signal: '#3DFF8B',     // phosphor green — the signature accent
        signalDim: '#1F8C53',
        warn: '#FFB02E',       // amber for medium severity
        crit: '#FF4D4D',       // red for high/critical severity
        paper: '#E9F2EC',      // primary text, slightly cool white
        muted: '#7C9186',      // secondary text
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        scan: 'repeating-linear-gradient(to bottom, rgba(61,255,139,0.04) 0px, rgba(61,255,139,0.04) 1px, transparent 1px, transparent 3px)',
      },
    },
  },
  plugins: [],
}
