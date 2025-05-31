// tailwind.config.js
module.exports = {
  content: [
    "./app/templates/**/*.html",
    "./app/static/js/**/*.js",
  ],
  darkMode: 'class', 
  theme: {
    extend: {
      colors: {
        'plex-bg': '#141414',
        'plex-surface': '#282828',
        'plex-border': '#383838',
        'plex-text-primary': '#e5e5e5',
        'plex-text-secondary': '#808080',
        'plex-accent': '#e5a00d',
        'plex-accent-hover': '#f0ad4e',
        // Add light theme colors if you want to make them distinct from Tailwind defaults
        'light-bg': '#f8f9fa', // Example: Bootstrap's light gray
        'light-text': '#212529', // Example: Bootstrap's dark text
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}