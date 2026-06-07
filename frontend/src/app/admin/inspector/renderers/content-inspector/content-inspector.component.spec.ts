import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { ContentInspectorComponent } from './content-inspector.component';
import type { ApiContent, ContentStatus } from '../../../../core/models/api.model';

const baseContent: ApiContent = {
  id: 'c1',
  slug: 'sample',
  title: 'Sample',
  body: 'body',
  excerpt: 'excerpt',
  type: 'article',
  status: 'draft',
  tags: [],
  topics: [],
  cover_image: null,
  source: null,
  source_type: null,
  series_id: null,
  series_order: null,
  is_public: false,
  ai_metadata: null,
  reading_time_min: 1,
  published_at: null,
  created_at: '2026-05-01T00:00:00Z',
  updated_at: '2026-05-01T00:00:00Z',
};

describe('ContentInspectorComponent', () => {
  let fixture: ComponentFixture<ContentInspectorComponent>;
  let httpMock: HttpTestingController;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(ContentInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  async function loadWithStatus(status: ContentStatus): Promise<void> {
    fixture.componentRef.setInput('id', baseContent.id);
    fixture.detectChanges();
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/knowledge/content/${baseContent.id}`),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      r.flush({ data: { ...baseContent, status } });
    }
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  function publishButton(): Element | null {
    const el = fixture.nativeElement as HTMLElement;
    return el.querySelector('[data-testid="content-publish"]');
  }

  it('should not expose Publish when status is draft', async () => {
    setupFixture();
    await loadWithStatus('draft');
    expect(publishButton()).toBeNull();
  });

  it('should expose Publish when status is review', async () => {
    setupFixture();
    await loadWithStatus('review');
    expect(publishButton()).not.toBeNull();
  });

  it('should not expose Publish when status is archived', async () => {
    setupFixture();
    await loadWithStatus('archived');
    expect(publishButton()).toBeNull();
  });
});
