import type { TokenizerAndRendererExtension, Tokens, Token } from 'marked';

/**
 * Obsidian-parity marked extensions: highlight (`==text==`), callouts
 * (`> [!type] title`), and wikilinks (`[[target|alias]]`). Each is a real
 * tokenizer/renderer pair so it composes with the rest of markdown (it respects
 * code spans, nests inline formatting, etc.) instead of a fragile HTML regex.
 */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

interface HighlightToken extends Tokens.Generic {
  inner: Token[];
}

/** `==text==` → `<mark>text</mark>` (Obsidian highlight). */
const highlightExtension: TokenizerAndRendererExtension = {
  name: 'highlight',
  level: 'inline',
  start(src: string) {
    return src.indexOf('==');
  },
  tokenizer(src: string) {
    const match = /^==(?=\S)([\s\S]*?\S)==/.exec(src);
    if (!match) {
      return undefined;
    }
    return {
      type: 'highlight',
      raw: match[0],
      inner: this.lexer.inlineTokens(match[1]),
    } satisfies HighlightToken;
  },
  renderer(token) {
    const t = token as HighlightToken;
    return `<mark>${this.parser.parseInline(t.inner)}</mark>`;
  },
};

interface WikilinkToken extends Tokens.Generic {
  target: string;
  label: string;
}

/**
 * `[[target]]` / `[[target|alias]]` → a styled, non-link reference. Published
 * content has no note-graph to resolve against, so a link could 404 — the
 * reference is rendered as styled text that preserves the author's intent
 * without a broken anchor.
 */
const wikilinkExtension: TokenizerAndRendererExtension = {
  name: 'wikilink',
  level: 'inline',
  start(src: string) {
    return src.indexOf('[[');
  },
  tokenizer(src: string) {
    const match = /^\[\[([^\]|]+?)(?:\|([^\]]+?))?\]\]/.exec(src);
    if (!match) {
      return undefined;
    }
    const target = match[1].trim();
    return {
      type: 'wikilink',
      raw: match[0],
      target,
      label: (match[2] ?? match[1]).trim(),
    } satisfies WikilinkToken;
  },
  renderer(token) {
    const t = token as WikilinkToken;
    return `<span class="wikilink" title="${escapeHtml(t.target)}">${escapeHtml(t.label)}</span>`;
  },
};

interface CalloutToken extends Tokens.Generic {
  calloutType: string;
  title: string;
  body: Token[];
}

/**
 * Obsidian callouts: `> [!type] optional title` followed by `> ` body lines →
 * a titled callout box. The body is parsed as block markdown so it can hold
 * paragraphs, lists, and code. A block-level extension runs before the built-in
 * blockquote tokenizer, so `> [!type]` becomes a callout, not a quote.
 */
const calloutExtension: TokenizerAndRendererExtension = {
  name: 'callout',
  level: 'block',
  start(src: string) {
    return src.match(/^ {0,3}> *\[!/m)?.index;
  },
  tokenizer(src: string) {
    const rule =
      /^ {0,3}> *\[!(\w+)\][+-]?([^\n]*)(?:\n((?: {0,3}>[^\n]*(?:\n|$))*))?/;
    const match = rule.exec(src);
    if (!match) {
      return undefined;
    }
    const bodyRaw = (match[3] ?? '').replace(/^ {0,3}> ?/gm, '');
    return {
      type: 'callout',
      raw: match[0],
      calloutType: match[1].toLowerCase(),
      title: match[2].trim(),
      body: this.lexer.blockTokens(bodyRaw),
    } satisfies CalloutToken;
  },
  renderer(token) {
    const t = token as CalloutToken;
    const title =
      t.title || t.calloutType.charAt(0).toUpperCase() + t.calloutType.slice(1);
    const body = this.parser.parse(t.body);
    return `<div class="callout callout-${escapeHtml(t.calloutType)}"><div class="callout-title">${escapeHtml(title)}</div><div class="callout-body">${body}</div></div>`;
  },
};

/** Every Obsidian-parity extension, in registration order. */
export const obsidianExtensions: TokenizerAndRendererExtension[] = [
  highlightExtension,
  wikilinkExtension,
  calloutExtension,
];
