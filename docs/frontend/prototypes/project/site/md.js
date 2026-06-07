/* koopa.dev — tiny Markdown renderer. window.renderMarkdown(md) -> { html, toc } */
(function () {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const slug = (s) => s.toLowerCase().replace(/[^\w]+/g, "-").replace(/^-+|-+$/g, "");
  const inline = (s) => esc(s)
    .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  window.renderMarkdown = function (md) {
    const lines = (md || "").split("\n");
    const out = [];
    const toc = [];
    let i = 0;
    let droppedTitle = false;
    while (i < lines.length) {
      let line = lines[i];

      // skip a single leading top-level "# Title" (the page shows it separately)
      if (!droppedTitle && /^#\s+/.test(line)) { droppedTitle = true; i++; while (i < lines.length && lines[i].trim() === "") i++; continue; }

      // fenced code
      if (/^```/.test(line)) {
        const lang = line.replace(/^```/, "").trim();
        const buf = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) { buf.push(lines[i]); i++; }
        i++; // closing fence
        out.push(`<pre data-lang="${esc(lang)}"><code>${esc(buf.join("\n"))}</code></pre>`);
        continue;
      }
      // headings
      let m;
      if ((m = /^###\s+(.*)$/.exec(line))) { const id = slug(m[1]); toc.push({ id, text: m[1], level: 3 }); out.push(`<h3 id="${id}">${inline(m[1])}</h3>`); i++; continue; }
      if ((m = /^##\s+(.*)$/.exec(line))) { const id = slug(m[1]); toc.push({ id, text: m[1], level: 2 }); out.push(`<h2 id="${id}">${inline(m[1])}</h2>`); i++; continue; }
      // blockquote (consecutive)
      if (/^>\s?/.test(line)) {
        const buf = [];
        while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, "")); i++; }
        out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`);
        continue;
      }
      // ordered list
      if (/^\d+\.\s+/.test(line)) {
        const buf = [];
        while (i < lines.length && /^\d+\.\s+/.test(lines[i])) { buf.push(lines[i].replace(/^\d+\.\s+/, "")); i++; }
        out.push(`<ol>${buf.map((b) => `<li>${inline(b)}</li>`).join("")}</ol>`);
        continue;
      }
      // unordered list
      if (/^[-*]\s+/.test(line)) {
        const buf = [];
        while (i < lines.length && /^[-*]\s+/.test(lines[i])) { buf.push(lines[i].replace(/^[-*]\s+/, "")); i++; }
        out.push(`<ul>${buf.map((b) => `<li>${inline(b)}</li>`).join("")}</ul>`);
        continue;
      }
      // blank
      if (line.trim() === "") { i++; continue; }
      // paragraph (consecutive non-blank, non-special)
      const buf = [];
      while (i < lines.length && lines[i].trim() !== "" && !/^(#{1,3}\s|```|>\s?|[-*]\s+|\d+\.\s+)/.test(lines[i])) { buf.push(lines[i]); i++; }
      out.push(`<p>${inline(buf.join(" "))}</p>`);
    }
    return { html: out.join("\n"), toc };
  };
})();
