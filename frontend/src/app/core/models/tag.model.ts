export interface Tag {
  id: string;
  name: string;
  slug: string;
  description?: string;
  color?: string;
  articleCount: number;
}

export interface TagCloud {
  tag: Tag;
  weight: number;
}