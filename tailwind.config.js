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
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"]
      }
    }
  },
  plugins: []
};
