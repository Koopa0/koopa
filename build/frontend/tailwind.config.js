/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./internal/web/**/*.templ",
    "./internal/web/**/*.go",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Primary palette (Blue)
        primary: {
          50:  '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        // Surface colors for dark mode
        surface: {
          50:  '#fafafa',
          100: '#f5f5f5',
          200: '#e5e5e5',
          300: '#d4d4d4',
          400: '#a3a3a3',
          500: '#737373',
          600: '#525252',
          700: '#404040',
          800: '#262626',
          850: '#1f1f1f',
          900: '#171717',
          950: '#0a0a0a',
        },
        // Semantic colors
        success: {
          50:  '#f0fdf4',
          100: '#dcfce7',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
        },
        error: {
          50:  '#fef2f2',
          100: '#fee2e2',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
        },
        warning: {
          50:  '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',  // Used in border-warning-300
          400: '#fbbf24',  // Used in text-warning-400
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',  // Used in text-warning-800
          900: '#78350f',  // Used in bg-warning-900/20
        },
      },
      // Animation for streaming indicator
      animation: {
        'pulse': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      // Material Design easing
      transitionTimingFunction: {
        'emphasized': 'cubic-bezier(0.2, 0, 0, 1.0)',
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
