import { inject, Injectable, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { marked } from 'marked';
import hljs from 'highlight.js';
import DOMPurify from 'isomorphic-dompurify';

/** Allowed HTML tags and attributes for sanitized markdown output */
const PURIFY_CONFIG = {
  RETURN_DOM_FRAGMENT: false,
  RETURN_DOM: false,
  ALLOWED_TAGS: [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'br', 'hr',
    'ul', 'ol', 'li',
    'blockquote', 'pre', 'code',
    'strong', 'em', 'del', 's', 'mark', 'sub', 'sup',
    'a', 'img',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'div', 'span',
    'details', 'summary',
    'input',
  ],
  ALLOWED_ATTR: [
    'id', 'class', 'href', 'src', 'alt', 'title', 'target', 'rel',
    'data-mermaid-code',
    'width', 'height',
    'colspan', 'rowspan',
    'type', 'checked', 'disabled',
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
  }

  parse(markdown: string): string {
    // Parse markdown and then highlight code blocks
    let html = marked.parse(markdown) as string;

    // Add IDs to headings for TOC navigation
    html = this.addHeadingIds(html);

    // Process mermaid diagrams before highlighting
    // (highlightCode would change the class and prevent mermaid matching)
    html = this.processMermaidDiagrams(html);

    // Apply syntax highlighting to code blocks
    html = this.highlightCode(html);

    // Sanitize HTML to prevent XSS attacks
    html = DOMPurify.sanitize(html, PURIFY_CONFIG) as string;

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
    // Use regex to find and replace code blocks with highlighted versions
    return html.replace(
      /<pre><code class="language-(\w+)">([\s\S]*?)<\/code><\/pre>/g,
      (match, lang, code) => {
        try {
          if (lang && hljs.getLanguage(lang)) {
            const highlighted = hljs.highlight(code, { language: lang }).value;
            return `<pre><code class="language-${lang} hljs">${highlighted}</code></pre>`;
          }
        } catch {
          // Syntax highlighting failed, fallback to auto-detection
        }
        try {
          const highlighted = hljs.highlightAuto(code).value;
          return `<pre><code class="hljs">${highlighted}</code></pre>`;
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
        // Generate a unique ID for each diagram
        const diagramId = 'mermaid-' + Math.random().toString(36).substr(2, 9);

        // Return a div that will be processed by mermaid.js
        return `<div class="mermaid-diagram" id="${diagramId}" data-mermaid-code="${encodeURIComponent(code.trim())}">${code.trim()}</div>`;
      },
    );
  }

  // Render mermaid diagrams as placeholder (temporary solution before mermaid.js integration)
  initializeMermaid(): void {
    // Guard against SSR — document is not available on the server
    if (!this.isBrowser) {
      return;
    }

    setTimeout(() => {
      const mermaidElements = document.querySelectorAll<HTMLElement>('.mermaid-diagram');
      mermaidElements.forEach((element) => {
        const code = decodeURIComponent(
          element.getAttribute('data-mermaid-code') ?? '',
        );
        if (code) {
          // Clear and use DOM API to safely construct elements, avoiding innerHTML XSS risk
          element.textContent = '';
          element.classList.add(
            'rounded-lg', 'border-2', 'border-dashed', 'border-zinc-600',
            'bg-zinc-100', 'p-5', 'text-center', 'font-mono', 'text-zinc-600',
            'dark:bg-zinc-800', 'dark:border-zinc-500', 'dark:text-zinc-400',
          );

          const title = document.createElement('div');
          title.className = 'mb-2 font-bold';
          title.textContent = 'Mermaid Diagram';
          element.appendChild(title);

          const subtitle = document.createElement('div');
          subtitle.className = 'mb-4 text-sm';
          subtitle.textContent = 'Diagram type identified, waiting for Mermaid.js to load...';
          element.appendChild(subtitle);

          const pre = document.createElement('pre');
          pre.className = 'rounded-sm bg-white p-2.5 text-left dark:bg-zinc-900';
          pre.textContent = code;
          element.appendChild(pre);
        }
      });
    }, 100);
  }
}
