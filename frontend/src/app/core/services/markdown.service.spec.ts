import { TestBed } from '@angular/core/testing';
import { MarkdownService } from './markdown.service';

describe('MarkdownService', () => {
  let service: MarkdownService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(MarkdownService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should parse basic markdown to HTML', () => {
    const result = service.parse('**bold text**');
    expect(result).toContain('<strong>bold text</strong>');
  });

  it('should parse headings', () => {
    const result = service.parse('## Hello World');
    expect(result).toContain('<h2');
    expect(result).toContain('Hello World');
  });

  it('should add IDs to headings for TOC navigation', () => {
    const result = service.parse('## My Heading');
    expect(result).toMatch(/id="my-heading"/);
  });

  it('should generate unique IDs for duplicate headings', () => {
    const result = service.parse('## Same\n\n## Same');
    expect(result).toContain('id="same"');
    expect(result).toContain('id="same-1"');
  });

  it('should parse inline code', () => {
    const result = service.parse('Use `console.log`');
    expect(result).toContain('<code>console.log</code>');
  });

  it('should parse code blocks with language', () => {
    const result = service.parse('```typescript\nconst x = 1;\n```');
    expect(result).toContain('<pre');
    expect(result).toContain('<code');
  });

  it('should carry the fence language onto pre[data-lang] for the CSS label', () => {
    const result = service.parse('```go\nfunc main() {}\n```');
    expect(result).toContain('data-lang="go"');
  });

  it('should not emit data-lang for fences without a language', () => {
    const result = service.parse('```\nplain text\n```');
    expect(result).not.toContain('data-lang');
  });

  it('should parse links', () => {
    const result = service.parse('[Google](https://google.com)');
    expect(result).toContain('href="https://google.com"');
    expect(result).toContain('Google');
  });

  it('should parse lists', () => {
    const result = service.parse('- item 1\n- item 2');
    expect(result).toContain('<ul>');
    expect(result).toContain('<li>');
  });

  it('should handle empty input', () => {
    const result = service.parse('');
    expect(result).toBeDefined();
  });

  it('should process mermaid code blocks', () => {
    const result = service.parse('```mermaid\ngraph TD\nA-->B\n```');
    expect(result).toContain('mermaid-diagram');
  });

  it('should render ==text== as a highlight mark', () => {
    const result = service.parse('some ==highlighted== text');
    expect(result).toContain('<mark>highlighted</mark>');
  });

  it('should not treat == inside inline code as a highlight', () => {
    const result = service.parse('`a == b`');
    expect(result).not.toContain('<mark>');
    expect(result).toContain('<code>a == b</code>');
  });

  it('should render a titled callout block', () => {
    const result = service.parse('> [!warning] Be careful\n> watch out');
    expect(result).toContain('callout callout-warning');
    expect(result).toContain('Be careful');
    expect(result).toContain('watch out');
  });

  it('should default a callout title to its capitalized type', () => {
    const result = service.parse('> [!note]\n> just a note');
    expect(result).toContain('callout-note');
    expect(result).toContain('>Note<');
  });

  it('should render a wikilink alias as styled non-link text', () => {
    const result = service.parse('see [[Some Note|the note]] here');
    expect(result).toContain('class="wikilink"');
    expect(result).toContain('the note');
    expect(result).not.toContain('<a ');
  });
});
