export type NoteCategory = 'snippet' | 'config' | 'reading' | 'other';
export type NoteStatus = 'draft' | 'published';

export interface Note {
  id: string;
  slug: string;
  title: string;
  content: string;
  category: NoteCategory;
  tags: string[];
  publishedAt: Date;
  updatedAt: Date;
  status: NoteStatus;
}

export interface CreateNoteRequest {
  title: string;
  content: string;
  category: NoteCategory;
  tags: string[];
  status: NoteStatus;
}

export interface UpdateNoteRequest extends Partial<CreateNoteRequest> {
  id: string;
}
