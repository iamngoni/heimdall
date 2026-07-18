module.exports = {
  content: ["./templates/**/*.html"],
  safelist: [
    // Severity / status dot + tint classes applied dynamically via template logic
    "bg-crit", "bg-high", "bg-med", "bg-low",
    "text-crit-700", "text-high-700", "text-med-700", "text-low-700",
    "bg-crit-50", "bg-high-50", "bg-med-50", "bg-low-50", "bg-info-50",
    "text-crit", "text-high", "text-med", "text-low", "text-info-700",
    "border-crit-100", "border-med-200", "border-low-200", "border-info-200",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        serif: ["Source Serif 4", "Source Serif Pro", "Georgia", "serif"],
        mono: ["JetBrains Mono", "Fira Code", "ui-monospace", "monospace"],
      },
      colors: {
        // Surfaces
        paper: "#F6F7F5",
        // Graphite neutral ramp (text, borders, surfaces)
        ink: {
          50: "#F9FAFB", 100: "#F2F3F2", 150: "#ECEEED", 200: "#E4E7E5",
          300: "#D3D7D5", 400: "#9BA1A0", 500: "#6B7280", 600: "#4B5563",
          700: "#374151", 800: "#1F2933", 900: "#1F2328",
        },
        // Dark app rail
        sidebar: { DEFAULT: "#10161A", soft: "#1B2329", active: "#232D33" },
        // Brand teal
        brand: {
          50: "#E7F5F4", 100: "#C6E9E7", 200: "#9BD9D6",
          500: "#0FA3A3", 600: "#0C8585", 700: "#0A6C6C",
        },
        // Semantic severity/status (never decorative)
        crit: { 50: "#FCEDED", 100: "#F6C9C9", 200: "#F6C9C9", 500: "#E44C4C", 600: "#CE3B3B", 700: "#B23030", DEFAULT: "#E44C4C" },
        high: { 50: "#FDF0E7", 200: "#F8D5B8", 500: "#F5822B", 700: "#B85C13", DEFAULT: "#F5822B" },
        med:  { 50: "#FCF6E3", 200: "#F2E4A8", 500: "#EBB800", 700: "#8A6D00", DEFAULT: "#EBB800" },
        low:  { 50: "#E9F6EF", 200: "#BFE6D2", 500: "#1FB57A", 700: "#0F7A4E", DEFAULT: "#1FB57A" },
        info: { 50: "#EEF3FE", 200: "#CBDBFB", 500: "#3B82F6", 700: "#1D4ED8", DEFAULT: "#3B82F6" },
      },
      borderRadius: { xl2: "0.875rem" },
      letterSpacing: { tightest: "-0.03em", tighter2: "-0.02em" },
      maxWidth: { measure: "68ch", article: "720px" },
      boxShadow: {
        card: "0 1px 2px rgba(16,24,40,0.04), 0 4px 10px -2px rgba(16,24,40,0.05)",
        overlay: "0 4px 12px -2px rgba(16,24,40,0.08), 0 12px 28px -6px rgba(16,24,40,0.10)",
      },
    },
  },
  plugins: [],
};
