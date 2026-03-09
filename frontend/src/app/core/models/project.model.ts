export type ProjectStatus = 'completed' | 'in-progress' | 'maintained';

export interface Project {
  id: string;
  slug: string;
  title: string;
  description: string;
  longDescription?: string;
  coverImage?: string;
  techStack: string[];
  role: string;
  highlights: string[];
  githubUrl?: string;
  liveUrl?: string;
  featured: boolean;
  order: number;
  status: ProjectStatus;
  problem?: string;
  solution?: string;
  architecture?: string;
  results?: string;
  buildLogIds?: string[];
}

export interface CreateProjectRequest {
  title: string;
  slug: string;
  description: string;
  longDescription?: string;
  techStack: string[];
  role: string;
  highlights: string[];
  githubUrl?: string;
  liveUrl?: string;
  featured: boolean;
  order: number;
  status: ProjectStatus;
}

export interface UpdateProjectRequest extends Partial<CreateProjectRequest> {
  id: string;
}
