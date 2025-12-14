/** @type {import('tailwindcss').Config} */
module.exports = {
  // Paths are relative to where tailwindcss is executed from (project root)
  // NOT relative to this config file location
  content: [
    "./internal/web/**/*.templ",
    "./internal/web/**/*.go",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      // NO custom color tokens - use Tailwind UI native classes
      // - User messages: bg-indigo-500
      // - AI messages: bg-gray-700
      // - Backgrounds: bg-gray-900, bg-gray-800
      // - Borders: border-white/10
      // - Text: text-white, text-gray-400
      //
      // Animation for streaming indicator (preserved)
      animation: {
        'pulse': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
