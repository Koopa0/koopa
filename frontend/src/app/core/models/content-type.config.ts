import { FileText, Pen, Code, BookOpen, Newspaper } from 'lucide-angular';
import type { ContentType } from './api.model';

export interface ContentTypeConfig {
  label: string;
  labelZh: string;
  icon: typeof FileText;
  route: string;
  badgeClasses: string;
  /** Whether it can be created in the editor */
  editorEnabled: boolean;
  /** Whether it has a public detail page */
  hasPublicPage: boolean;
}

export const CONTENT_TYPE_CONFIG: Record<ContentType, ContentTypeConfig> = {
  article: {
    label: 'Article',
    labelZh: 'Article',
    icon: FileText,
    route: '/articles',
    badgeClasses: 'border-sky-700 bg-sky-900/30 text-sky-400',
    editorEnabled: true,
    hasPublicPage: true,
  },
  essay: {
    label: 'Essay',
    labelZh: 'Essay',
    icon: Pen,
    route: '/essays',
    badgeClasses: 'border-violet-700 bg-violet-900/30 text-violet-400',
    editorEnabled: true,
    hasPublicPage: true,
  },
  'build-log': {
    label: 'Build Log',
    labelZh: 'Build Log',
    icon: Code,
    route: '/build-logs',
    badgeClasses: 'border-amber-700 bg-amber-900/30 text-amber-400',
    editorEnabled: false,
    hasPublicPage: true,
  },
  til: {
    label: 'TIL',
    labelZh: 'TIL',
    icon: BookOpen,
    route: '/til',
    badgeClasses: 'border-emerald-700 bg-emerald-900/30 text-emerald-400',
    editorEnabled: false,
    hasPublicPage: true,
  },
  digest: {
    label: 'Digest',
    labelZh: 'Digest',
    icon: Newspaper,
    route: '/digests',
    badgeClasses: 'border-zinc-600 bg-zinc-800 text-zinc-300',
    editorEnabled: false,
    hasPublicPage: false,
  },
};

/** Get content type label (localized) */
export function contentTypeLabel(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.labelZh ?? type;
}

/** Get content type English label */
export function contentTypeLabelEn(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.label ?? type;
}

/** Get content type frontend route prefix */
export function contentTypeRoute(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.route ?? '/articles';
}

/** Get content types with public pages (excludes digest) */
export function publicContentTypes(): ContentType[] {
  return (
    Object.entries(CONTENT_TYPE_CONFIG) as [ContentType, ContentTypeConfig][]
  )
    .filter(([, config]) => config.hasPublicPage)
    .map(([type]) => type);
}
