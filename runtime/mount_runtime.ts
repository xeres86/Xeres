// ---- xeres dom runtime ----
// R22: every interpolated view value is HTML-escaped before it reaches the DOM,
// so `text userInput` can never inject markup. `raw(...)` is the audited opt-out.
function __esc(v: unknown): string {
  return String(v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
type XHandler = (key?: string) => void | Promise<void>;
const __handlers = new Map<string, XHandler>();
const __binds = new Map<string, (v: string | boolean | number) => void>();
let __draw: (() => void) | null = null;   // set by mount; called on reactive updates
export function on(name: string, fn: XHandler): void { __handlers.set(name, fn); }
export function onBind(name: string, fn: (v: string | boolean | number) => void): void { __binds.set(name, fn); }

// Render a screen into `el`, then wire events. Clicks re-render afterwards;
// input binds update state WITHOUT re-rendering (so the field keeps focus).
export function mount(el: HTMLElement, render: () => string): void {
  const draw = () => {
    el.innerHTML = render();
    el.querySelectorAll<HTMLElement>("[data-onclick]").forEach((node) => {
      const name = node.getAttribute("data-onclick") || "";
      const key = node.getAttribute("data-key") || undefined;
      node.onclick = async () => { const h = __handlers.get(name); if (h) await h(key); draw(); };
    });
    // Client-router links: intercept the click (no full reload) and navigate.
    el.querySelectorAll<HTMLAnchorElement>("[data-link]").forEach((node) => {
      const name = node.getAttribute("data-link") || "";
      node.onclick = (e) => { e.preventDefault(); __navigate(name); };
    });
    el.querySelectorAll<HTMLInputElement>("[data-bind]").forEach((node) => {
      const name = node.getAttribute("data-bind") || "";
      const b = __binds.get(name);
      if (!b) return;
      if (node.type === "checkbox") { node.onchange = () => b(node.checked); }
      else if (node.type === "number") {
        // numeric input -> a real JS number (NaN when empty -> 0), so the bound
        // Int/Float state cell never silently becomes a string.
        const num = () => { const n = node.valueAsNumber; b(Number.isNaN(n) ? 0 : n); };
        node.oninput = num; node.onchange = num;
      }
      else { node.oninput = () => b(node.value); node.onchange = () => b(node.value); }
    });
  };
  __draw = draw;
  draw();
}
