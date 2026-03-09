import { TestBed } from '@angular/core/testing';
import { Meta, Title } from '@angular/platform-browser';
import { PLATFORM_ID } from '@angular/core';
import { SeoService, PageMeta } from './seo.service';

describe('SeoService', () => {
  let service: SeoService;
  let meta: Meta;
  let title: Title;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
    });
    service = TestBed.inject(SeoService);
    meta = TestBed.inject(Meta);
    title = TestBed.inject(Title);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should set page title with site name suffix', () => {
    service.updateMeta({ title: 'Test Page', description: 'Test' });
    expect(title.getTitle()).toBe('Test Page | koopa0.dev');
  });

  it('should set meta description', () => {
    service.updateMeta({
      title: 'Test',
      description: 'This is a test description',
    });
    const tag = meta.getTag('name="description"');
    expect(tag?.content).toBe('This is a test description');
  });

  it('should set Open Graph tags', () => {
    service.updateMeta({
      title: 'OG Test',
      description: 'OG Description',
      ogTitle: 'Custom OG Title',
      ogUrl: 'https://koopa0.dev/test',
    });
    const ogTitle = meta.getTag('property="og:title"');
    expect(ogTitle?.content).toBe('Custom OG Title');

    const ogUrl = meta.getTag('property="og:url"');
    expect(ogUrl?.content).toBe('https://koopa0.dev/test');
  });

  it('should fall back to title when ogTitle is not provided', () => {
    service.updateMeta({ title: 'Fallback Test', description: 'Test' });
    const ogTitle = meta.getTag('property="og:title"');
    expect(ogTitle?.content).toBe('Fallback Test');
  });

  it('should set Twitter card tags', () => {
    service.updateMeta({
      title: 'Twitter Test',
      description: 'Desc',
      twitterCard: 'summary_large_image',
    });
    const card = meta.getTag('name="twitter:card"');
    expect(card?.content).toBe('summary_large_image');
  });

  it('should set noindex when specified', () => {
    service.updateMeta({
      title: 'NoIndex',
      description: 'Hidden page',
      noIndex: true,
    });
    const robots = meta.getTag('name="robots"');
    expect(robots?.content).toBe('noindex, nofollow');
  });

  it('should remove robots tag when noIndex is false', () => {
    service.updateMeta({
      title: 'NoIndex',
      description: 'Test',
      noIndex: true,
    });
    service.updateMeta({
      title: 'Index',
      description: 'Test',
      noIndex: false,
    });
    const robots = meta.getTag('name="robots"');
    expect(robots).toBeNull();
  });

  it('should set JSON-LD script tag', () => {
    service.updateMeta({
      title: 'JsonLd',
      description: 'Test',
      jsonLd: { '@type': 'WebSite', name: 'Test' },
    });
    const script = document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    expect(script).not.toBeNull();
    expect(script?.textContent).toContain('"@type":"WebSite"');
  });

  it('should replace existing JSON-LD on subsequent calls', () => {
    service.updateMeta({
      title: 'First',
      description: 'Test',
      jsonLd: { '@type': 'WebSite', name: 'First' },
    });
    service.updateMeta({
      title: 'Second',
      description: 'Test',
      jsonLd: { '@type': 'Person', name: 'Second' },
    });
    const scripts = document.querySelectorAll(
      'script[type="application/ld+json"][data-seo]',
    );
    expect(scripts.length).toBe(1);
    expect(scripts[0].textContent).toContain('"@type":"Person"');
  });

  it('should clear meta with clearMeta()', () => {
    service.updateMeta({
      title: 'Test',
      description: 'Test',
      jsonLd: { '@type': 'WebSite' },
    });
    service.clearMeta();
    const script = document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    expect(script).toBeNull();
  });

  it('should set canonical URL', () => {
    service.updateMeta({
      title: 'Canonical',
      description: 'Test',
      canonicalUrl: 'https://koopa0.dev/canonical',
    });
    const link = document.querySelector('link[rel="canonical"]');
    expect(link?.getAttribute('href')).toBe('https://koopa0.dev/canonical');
  });
});
