import { Injectable, inject, PLATFORM_ID } from '@angular/core';
import { Meta, Title } from '@angular/platform-browser';
import { DOCUMENT } from '@angular/common';

export interface PageMeta {
  title: string;
  description: string;
  ogTitle?: string;
  ogDescription?: string;
  ogImage?: string;
  ogUrl?: string;
  ogType?: 'website' | 'article' | 'profile';
  twitterCard?: 'summary' | 'summary_large_image';
  canonicalUrl?: string;
  noIndex?: boolean;
  jsonLd?: Record<string, unknown>;
}

const SITE_NAME = 'koopa0.dev';
const DEFAULT_DESCRIPTION =
  'Software Engineer - Technical articles and personal projects';
const DEFAULT_IMAGE = 'https://koopa0.dev/og-image.png';

@Injectable({ providedIn: 'root' })
export class SeoService {
  private readonly meta = inject(Meta);
  private readonly titleService = inject(Title);
  private readonly document = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);

  updateMeta(pageMeta: PageMeta): void {
    const title = `${pageMeta.title} | ${SITE_NAME}`;
    this.titleService.setTitle(title);

    // Base meta tags
    this.meta.updateTag({
      name: 'description',
      content: pageMeta.description || DEFAULT_DESCRIPTION,
    });

    if (pageMeta.noIndex) {
      this.meta.updateTag({ name: 'robots', content: 'noindex, nofollow' });
    } else {
      this.meta.removeTag('name="robots"');
    }

    // Open Graph
    this.meta.updateTag({
      property: 'og:title',
      content: pageMeta.ogTitle || pageMeta.title,
    });
    this.meta.updateTag({
      property: 'og:description',
      content:
        pageMeta.ogDescription || pageMeta.description || DEFAULT_DESCRIPTION,
    });
    this.meta.updateTag({
      property: 'og:image',
      content: pageMeta.ogImage || DEFAULT_IMAGE,
    });
    this.meta.updateTag({
      property: 'og:type',
      content: pageMeta.ogType || 'website',
    });
    this.meta.updateTag({ property: 'og:site_name', content: SITE_NAME });

    if (pageMeta.ogUrl) {
      this.meta.updateTag({ property: 'og:url', content: pageMeta.ogUrl });
    }

    // Twitter Card
    this.meta.updateTag({
      name: 'twitter:card',
      content: pageMeta.twitterCard || 'summary',
    });
    this.meta.updateTag({
      name: 'twitter:title',
      content: pageMeta.ogTitle || pageMeta.title,
    });
    this.meta.updateTag({
      name: 'twitter:description',
      content:
        pageMeta.ogDescription || pageMeta.description || DEFAULT_DESCRIPTION,
    });
    this.meta.updateTag({
      name: 'twitter:image',
      content: pageMeta.ogImage || DEFAULT_IMAGE,
    });

    // Canonical URL
    this.updateCanonicalUrl(pageMeta.canonicalUrl || pageMeta.ogUrl);

    // JSON-LD
    if (pageMeta.jsonLd) {
      this.setJsonLd(pageMeta.jsonLd);
    }
  }

  private updateCanonicalUrl(url?: string): void {
    let link: HTMLLinkElement | null = this.document.querySelector(
      'link[rel="canonical"]',
    );

    if (url) {
      if (!link) {
        link = this.document.createElement('link');
        link.setAttribute('rel', 'canonical');
        this.document.head.appendChild(link);
      }
      link.setAttribute('href', url);
    } else if (link) {
      link.remove();
    }
  }

  private setJsonLd(data: Record<string, unknown>): void {
    const existingScript = this.document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    if (existingScript) {
      existingScript.remove();
    }

    const script = this.document.createElement('script');
    script.setAttribute('type', 'application/ld+json');
    script.setAttribute('data-seo', 'true');
    script.textContent = JSON.stringify(data);
    this.document.head.appendChild(script);
  }

  /**
   * Clear all SEO-related meta tags (called on route change)
   */
  clearMeta(): void {
    const existingScript = this.document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    if (existingScript) {
      existingScript.remove();
    }
  }
}
