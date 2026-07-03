import { inject, Injectable, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { marked } from 'marked';
import hljs from 'highlight.js';
import DOMPurify from 'dompurify';
import { obsidianExtensions } from './markdown-extensions';

/** Allowed HTML tags and attributes for sanitized markdown output */
const PURIFY_CONFIG = {
  RETURN_DOM_FRAGMENT: false,
  RETURN_DOM: false,
  ALLOWED_TAGS: [
    'h1',
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'p',
    'br',
    'hr',
    'ul',
    'ol',
    'li',
    'blockquote',
    'pre',
    'code',
    'strong',
    'em',
    'del',
    's',
    'mark',
    'sub',
    'sup',
    'a',
    'img',
    'table',
    'thead',
    'tbody',
    'tr',
    'th',
    'td',
    'div',
    'span',
    'details',
    'summary',
    'input',
  ],
  ALLOWED_ATTR: [
    'id',
    'class',
    'href',
    'src',
    'alt',
    'title',
    'target',
    'rel',
    'data-mermaid-code',
    'data-lang',
    'width',
    'height',
    'colspan',
    'rowspan',
    'type',
    'checked',
    'disabled',
    'open',
  ],
  ALLOW_DATA_ATTR: false,
};

@Injectable({
  providedIn: 'root',
})
export class MarkdownService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly isBrowser = isPlatformBrowser(this.platformId);

  constructor() {
    marked.setOptions({
      gfm: true,
      breaks: true,
    });
    // Obsidian-parity syntax: ==highlight==, > [!callout], [[wikilink]].
    marked.use({ extensions: obsidianExtensions });
  }

  parse(markdown: string): string {
    // Strip a leading YAML frontmatter block. Notes authored in Obsidian carry
    // `--- … ---` properties (type/status/domain/topics); when a body is pasted
    // in whole, that block must not render as a table/hr/heading.
    const body = markdown.replace(/^\uFEFF?---\r?\n[\s\S]*?\r?\n---\r?\n+/, '');

    // Parse markdown and then highlight code blocks
    let html = marked.parse(body) as string;

    // Add IDs to headings for TOC navigation
    html = this.addHeadingIds(html);

    // Process mermaid diagrams before highlighting
    // (highlightCode would change the class and prevent mermaid matching)
    html = this.processMermaidDiagrams(html);

    // Apply syntax highlighting to code blocks
    html = this.highlightCode(html);

    // Sanitize HTML to prevent XSS attacks
    // Skip on SSR: DOMPurify requires browser DOM; content from own backend is trusted; browser-side will re-sanitize after hydration
    if (this.isBrowser) {
      html = DOMPurify.sanitize(html, PURIFY_CONFIG) as string;
    }

    return html;
  }

  private addHeadingIds(html: string): string {
    const usedIds = new Set<string>();
    return html.replace(
      /<h([1-6])([^>]*)>(.*?)<\/h[1-6]>/gi,
      (_match, level: string, attrs: string, text: string) => {
        // Skip if already has an id
        if (/id="/.test(attrs)) {
          return _match;
        }
        const cleanText = text.replace(/<[^>]*>/g, '');
        let slug =
          cleanText
            .toLowerCase()
            .replace(/[^\w\u4e00-\u9fff]+/g, '-')
            .replace(/^-+|-+$/g, '') || 'heading';

        // Ensure unique IDs
        if (usedIds.has(slug)) {
          let counter = 1;
          while (usedIds.has(`${slug}-${counter}`)) {
            counter++;
          }
          slug = `${slug}-${counter}`;
        }
        usedIds.add(slug);

        return `<h${level} id="${slug}"${attrs}>${text}</h${level}>`;
      },
    );
  }

  private highlightCode(html: string): string {
    // Use regex to find and replace code blocks with highlighted versions.
    // The fence language is carried onto <pre data-lang> so CSS can render
    // the top-right language label on the reading surface.
    return html.replace(
      /<pre><code class="language-(\w+)">([\s\S]*?)<\/code><\/pre>/g,
      (match, lang, code) => {
        try {
          if (lang && hljs.getLanguage(lang)) {
            const highlighted = hljs.highlight(code, { language: lang }).value;
            return `<pre data-lang="${lang}"><code class="language-${lang} hljs">${highlighted}</code></pre>`;
          }
        } catch {
          // Syntax highlighting failed, fallback to auto-detection
        }
        try {
          const highlighted = hljs.highlightAuto(code).value;
          return `<pre data-lang="${lang}"><code class="hljs">${highlighted}</code></pre>`;
        } catch {
          return match;
        }
      },
    );
  }

  private processMermaidDiagrams(html: string): string {
    // Find mermaid code blocks and convert them to mermaid divs
    return html.replace(
      /<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g,
      (match, code) => {
        // Generate a unique ID for each diagram using crypto when available
        const randomId =
          typeof crypto !== 'undefined'
            ? Array.from(crypto.getRandomValues(new Uint8Array(6)), (b) =>
                b.toString(16).padStart(2, '0'),
              ).join('')
            : Math.floor(Math.random() * 1e12).toString(36);
        const diagramId = 'mermaid-' + randomId;

        // Return a div that will be processed by mermaid.js
        return `<div class="mermaid-diagram" id="${diagramId}" data-mermaid-code="${encodeURIComponent(code.trim())}">${code.trim()}</div>`;
      },
    );
  }

  /**
   * Render every mermaid diagram inside root into SVG. The markdown pass leaves
   * each ```mermaid block as a `<div class="mermaid-diagram" data-mermaid-code>`
   * placeholder; this lazily loads mermaid (only when a diagram is present, so
   * it never enters the main bundle) and replaces each placeholder's content
   * with the rendered SVG. Browser-only — a no-op during SSR, so the source
   * text stays visible until hydration. isDark selects the light/dark theme;
   * re-call on theme change and only diagrams not yet rendered for the current
   * theme are touched.
   */
  async renderMermaid(root: HTMLElement, isDark: boolean): Promise<void> {
    if (!this.isBrowser) {
      return;
    }
    const theme = isDark ? 'dark' : 'light';
    const blocks = Array.from(
      root.querySelectorAll<HTMLElement>('.mermaid-diagram'),
    ).filter((el) => el.dataset['mermaidTheme'] !== theme);
    if (blocks.length === 0) {
      return;
    }

    const { default: mermaid } = await import('mermaid');
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: isDark ? 'dark' : 'default',
    });

    for (const el of blocks) {
      const code = decodeURIComponent(el.dataset['mermaidCode'] ?? '');
      if (!code) {
        continue;
      }
      try {
        const { svg } = await mermaid.render(`${el.id}-svg`, code);
        const parsed = new DOMParser().parseFromString(svg, 'image/svg+xml');
        const svgEl = parsed.documentElement;
        if (svgEl.nodeName.toLowerCase() !== 'svg') {
          continue; // parse error — keep the source-text fallback
        }
        // DOM-API replacement (no innerHTML); mermaid securityLevel:'strict'
        // sanitizes diagram content, DOMParser does not execute script.
        el.replaceChildren();
        el.appendChild(document.importNode(svgEl, true));
        el.dataset['mermaidTheme'] = theme;
      } catch {
        // Invalid diagram — leave the source text in place as a fallback.
      }
    }
  }
}
