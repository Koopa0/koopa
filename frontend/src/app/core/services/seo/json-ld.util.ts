/**
 * JSON-LD Schema utility functions
 *
 * Generate structured data to help search engines understand page content.
 */

import { environment } from '../../../../environments/environment';

const SITE_URL = environment.siteUrl;
const AUTHOR_NAME = 'Koopa';

export function buildWebSiteSchema(): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'koopa0.dev',
    url: SITE_URL,
    description:
      'Software Engineer - Technical articles and personal projects',
    author: buildPersonSchema(),
  };
}

export function buildPersonSchema(): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'Person',
    name: AUTHOR_NAME,
    url: SITE_URL,
    jobTitle: 'Software Engineer',
    sameAs: ['https://github.com/koopa0', 'https://linkedin.com/in/koopa0'],
  };
}

export function buildBlogPostingSchema(article: {
  title: string;
  description: string;
  url: string;
  publishedAt: string;
  updatedAt?: string;
  coverImage?: string;
  tags?: string[];
}): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: article.title,
    description: article.description,
    url: article.url,
    datePublished: article.publishedAt,
    ...(article.updatedAt && { dateModified: article.updatedAt }),
    ...(article.coverImage && {
      image: article.coverImage,
    }),
    author: {
      '@type': 'Person',
      name: AUTHOR_NAME,
      url: SITE_URL,
    },
    publisher: {
      '@type': 'Organization',
      name: 'koopa0.dev',
      url: SITE_URL,
    },
    ...(article.tags &&
      article.tags.length > 0 && {
        keywords: article.tags.join(', '),
      }),
    mainEntityOfPage: {
      '@type': 'WebPage',
      '@id': article.url,
    },
  };
}

export function buildCollectionPageSchema(collection: {
  name: string;
  description: string;
  url: string;
}): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'CollectionPage',
    name: collection.name,
    description: collection.description,
    url: collection.url,
    isPartOf: {
      '@type': 'WebSite',
      name: 'koopa0.dev',
      url: SITE_URL,
    },
  };
}

export function buildBreadcrumbSchema(
  items: { name: string; url: string }[],
): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: item.url,
    })),
  };
}
