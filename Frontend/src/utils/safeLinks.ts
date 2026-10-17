// Links rendered from model or scan output: only app paths and http(s) URLs become clickable.
/** "internal" for an app path (/x, not //x), "external" for http(s) URLs, "unsafe" for anything else. */
export function linkKind(href: string): "internal" | "external" | "unsafe" {
  const h = href.trim();
  if (h.startsWith("/") && !h.startsWith("//") && !h.startsWith("/\\")) return "internal";
  if (/^https?:\/\/[^\s]+$/i.test(h)) return "external";
  return "unsafe";
}
