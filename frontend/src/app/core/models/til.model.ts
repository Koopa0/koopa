export type TilStatus = 'draft' | 'published';

export interface TilEntry {
  id: string;
  slug: string;
  title: string;
  content: string;
  codeSnippet?: string;
  codeLanguage?: string;
  tags: string[];
  publishedAt: Date;
  status: TilStatus;
}

export interface CreateTilRequest {
  title: string;
  content: string;
  codeSnippet?: string;
  codeLanguage?: string;
  tags: string[];
  status: TilStatus;
}

export interface UpdateTilRequest extends Partial<CreateTilRequest> {
  id: string;
}
