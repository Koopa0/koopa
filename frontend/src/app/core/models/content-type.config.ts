import {
  FileText,
  Pen,
  Code,
  BookOpen,
  StickyNote,
  Bookmark,
  Newspaper,
} from 'lucide-angular';
import type { ContentType } from './api.model';

export interface ContentTypeConfig {
  label: string;
  labelZh: string;
  icon: typeof FileText;
  route: string;
  badgeClasses: string;
  /** 是否可在 editor 中建立 */
  editorEnabled: boolean;
  /** 是否有公開 detail 頁面 */
  hasPublicPage: boolean;
}

export const CONTENT_TYPE_CONFIG: Record<ContentType, ContentTypeConfig> = {
  article: {
    label: 'Article',
    labelZh: '文章',
    icon: FileText,
    route: '/articles',
    badgeClasses: 'border-sky-700 bg-sky-900/30 text-sky-400',
    editorEnabled: true,
    hasPublicPage: true,
  },
  essay: {
    label: 'Essay',
    labelZh: '隨筆',
    icon: Pen,
    route: '/essays',
    badgeClasses: 'border-violet-700 bg-violet-900/30 text-violet-400',
    editorEnabled: true,
    hasPublicPage: true,
  },
  'build-log': {
    label: 'Build Log',
    labelZh: '日誌',
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
  note: {
    label: 'Note',
    labelZh: '筆記',
    icon: StickyNote,
    route: '/notes',
    badgeClasses: 'border-zinc-600 bg-zinc-800 text-zinc-400',
    editorEnabled: false,
    hasPublicPage: true,
  },
  bookmark: {
    label: 'Bookmark',
    labelZh: '書籤',
    icon: Bookmark,
    route: '/bookmarks',
    badgeClasses: 'border-rose-700 bg-rose-900/30 text-rose-400',
    editorEnabled: false,
    hasPublicPage: true,
  },
  digest: {
    label: 'Digest',
    labelZh: '摘要',
    icon: Newspaper,
    route: '/digests',
    badgeClasses: 'border-zinc-600 bg-zinc-800 text-zinc-300',
    editorEnabled: false,
    hasPublicPage: false,
  },
};

/** 取得 content type 的中文 label */
export function contentTypeLabel(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.labelZh ?? type;
}

/** 取得 content type 的英文 label */
export function contentTypeLabelEn(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.label ?? type;
}

/** 取得 content type 的前端 route prefix */
export function contentTypeRoute(type: ContentType): string {
  return CONTENT_TYPE_CONFIG[type]?.route ?? '/articles';
}

/** 取得有公開頁面的 content types（排除 digest） */
export function publicContentTypes(): ContentType[] {
  return (Object.entries(CONTENT_TYPE_CONFIG) as [ContentType, ContentTypeConfig][])
    .filter(([, config]) => config.hasPublicPage)
    .map(([type]) => type);
}
