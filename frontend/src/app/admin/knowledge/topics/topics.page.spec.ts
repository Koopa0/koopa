import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { TopicsPageComponent } from './topics.page';

const TOPICS_URL = '/api/admin/knowledge/topics';

function makeTopic(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'topic-1',
    slug: 'system-design',
    name: 'System Design',
    description: '',
    icon: '',
    content_count: 4,
    sort_order: 0,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('TopicsPageComponent', () => {
  let fixture: ComponentFixture<TopicsPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TopicsPageComponent);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  async function flushTopics(
    topics: Record<string, unknown>[] = [makeTopic()],
  ): Promise<void> {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TOPICS_URL))
      .flush({ data: topics });
    await settle();
  }

  it('should list topics with published counts', async () => {
    await flushTopics();

    expect(el().querySelector('[data-testid="topic-row-system-design"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="topics-count"]')?.textContent?.trim(),
    ).toBe('1');
    expect(
      el().querySelector('[data-testid="topic-count-system-design"]')
        ?.textContent,
    ).toContain('4');
  });

  it('should PUT the topic rename to the admin topics endpoint', async () => {
    await flushTopics();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="topic-rename-system-design"]',
      )
      ?.click();
    await settle();

    const input = el().querySelector<HTMLInputElement>(
      '[data-testid="rename-input"]',
    );
    input!.value = 'Systems';
    input!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="rename-save"]')
      ?.click();
    await settle();

    const req = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${TOPICS_URL}/topic-1`),
    );
    expect(req.request.body).toEqual({ name: 'Systems' });
    req.flush({ data: makeTopic({ name: 'Systems' }) });
    await settle();

    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TOPICS_URL))
      .flush({ data: [makeTopic({ name: 'Systems' })] });
    await settle();
  });

  it('should show the topics error state when the topics endpoint fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TOPICS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'failed' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(el().querySelector('[data-testid="topics-error"]')).toBeTruthy();
  });
});
