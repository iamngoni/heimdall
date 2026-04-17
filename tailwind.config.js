module.exports = {
  content: [
    "./templates/**/*.html"
  ],
  safelist: [
    // Toast system (classes inside <template> elements / applied via JS)
    "text-[13px]", "h-[18px]", "w-[18px]", "h-[3px]",
    "text-emerald-500", "text-amber-500", "text-rose-500", "text-blue-500",
    "bg-emerald-500", "bg-amber-500", "bg-rose-500", "bg-blue-500",
    "bg-emerald-50", "bg-amber-50", "bg-rose-50",
    "border-emerald-300", "border-amber-300", "border-rose-300",
    // Severity dot + text (monochrome-aware palette, retained via config)
    "text-red-700", "text-amber-700", "text-neutral-900", "text-neutral-500",
    "bg-red-700", "bg-amber-700", "bg-neutral-900", "bg-neutral-500",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif"
        ],
        serif: [
          "Iowan Old Style",
          "Palatino Linotype",
          "Book Antiqua",
          "Georgia",
          "serif"
        ],
        mono: ["JetBrains Mono", "Fira Code", "monospace"]
      },
      colors: {
        ink: {
          50:  "#fafafa",
          100: "#f5f5f5",
          200: "#e5e5e5",
          300: "#d4d4d4",
          400: "#a3a3a3",
          500: "#737373",
          600: "#525252",
          700: "#404040",
          800: "#262626",
          900: "#111111"
        }
      },
      letterSpacing: {
        tightest: "-0.03em",
        tighter2: "-0.02em"
      },
      maxWidth: {
        measure: "68ch",
        article: "720px"
      }
    }
  },
  plugins: []
};
