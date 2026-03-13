import {
  buildWebSiteSchema,
  buildBlogPostingSchema,
  buildCollectionPageSchema,
  buildBreadcrumbSchema,
  buildPersonSchema,
} from './json-ld.util';

describe('JSON-LD Utilities', () => {
  it('should build WebSite schema', () => {
    const schema = buildWebSiteSchema();
    expect(schema['@type']).toBe('WebSite');
    expect(schema['name']).toBe('koopa0.dev');
  });

  it('should build Person schema', () => {
    const schema = buildPersonSchema();
    expect(schema['@type']).toBe('Person');
    expect(schema['name']).toBe('Koopa');
  });

  it('should build BlogPosting schema', () => {
    const schema = buildBlogPostingSchema({
      title: 'Test',
      description: 'Desc',
      url: 'https://example.com',
      publishedAt: '2026-01-01',
    });
    expect(schema['@type']).toBe('BlogPosting');
    expect(schema['headline']).toBe('Test');
  });

  it('should include optional BlogPosting fields', () => {
    const schema = buildBlogPostingSchema({
      title: 'T',
      description: 'D',
      url: 'https://x.com',
      publishedAt: '2026-01-01',
      updatedAt: '2026-02-01',
      coverImage: 'https://img.com/a.jpg',
      tags: ['Go', 'Angular'],
    });
    expect(schema['dateModified']).toBe('2026-02-01');
    expect(schema['image']).toBe('https://img.com/a.jpg');
    expect(schema['keywords']).toBe('Go, Angular');
  });

  it('should build CollectionPage schema', () => {
    const schema = buildCollectionPageSchema({
      name: 'Notes',
      description: 'D',
      url: 'https://x.com/notes',
    });
    expect(schema['@type']).toBe('CollectionPage');
  });

  it('should build Breadcrumb schema', () => {
    const schema = buildBreadcrumbSchema([
      { name: 'Home', url: '/' },
      { name: 'Articles', url: '/articles' },
    ]);
    expect(schema['@type']).toBe('BreadcrumbList');
    expect((schema['itemListElement'] as unknown[]).length).toBe(2);
  });
});
