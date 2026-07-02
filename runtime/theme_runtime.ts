// ---- xeres theme runtime (spec 26) ----
// Restore a manually-picked theme (if any) as early as possible in module
// evaluation, before `mount()` draws — the flip lands in the same paint as a
// normal cold load, no separate flash-of-wrong-theme pass.
(function () {
  const saved = localStorage.getItem("xeres-theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
})();
function __toggleTheme(): void {
  const html = document.documentElement;
  const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
  html.setAttribute("data-theme", next);
  localStorage.setItem("xeres-theme", next);
}
