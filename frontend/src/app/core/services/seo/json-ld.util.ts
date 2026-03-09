/**
 * JSON-LD Schema 工具函式
 *
 * 產生結構化資料，幫助搜尋引擎理解頁面內容。
 */

const SITE_URL = 'https://koopa0.dev';
const AUTHOR_NAME = 'Koopa';

export function buildWebSiteSchema(): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'koopa0.dev',
    url: SITE_URL,
    description:
      'Backend Engineer / Full-Stack Developer - 技術文章與個人作品集',
    author: buildPersonSchema(),
  };
}

export function buildPersonSchema(): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'Person',
    name: AUTHOR_NAME,
    url: SITE_URL,
    jobTitle: 'Backend Engineer',
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
