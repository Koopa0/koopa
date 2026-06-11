import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { TagsTopicsPageComponent } from './tags-topics.page';
import type { AdminTag } from '../../../core/services/tag.service';

const TAGS_URL = '/api/admin/knowledge/tags';
const TOPICS_URL = '/api/admin/knowledge/topics';

function makeTag(overrides: Partial<AdminTag> = {}): AdminTag {
  return {
    id: 'tag-1',
    slug: 'go',
    name: 'Go',
    description: '',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

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

describe('TagsTopicsPageComponent', () => {
  let fixture: ComponentFixture<TagsTopicsPageComponent>;
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
    fixture = TestBed.createComponent(TagsTopicsPageComponent);
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

  async function flushLists(
    tags: AdminTag[] = [makeTag(), makeTag({ id: 'tag-2', slug: 'pg', name: 'Postgres' })],
    topics: Record<string, unknown>[] = [makeTopic()],
  ): Promise<void> {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TAGS_URL))
      .flush({ data: tags });
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TOPICS_URL))
      .flush({ data: topics });
    await settle();
  }

  it('should list tags and topics with published counts', async () => {
    await flushLists();

    expect(el().querySelector('[data-testid="tag-row-go"]')).toBeTruthy();
    expect(el().querySelector('[data-testid="tag-row-pg"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="tags-count"]')?.textContent?.trim(),
    ).toBe('2');
    expect(
      el().querySelector('[data-testid="topic-count-system-design"]')
        ?.textContent,
    ).toContain('4');
  });

  it('should PUT the new name and reload when a tag rename is committed', async () => {
    await flushLists();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="tag-rename-go"]')
      ?.click();
    await settle();

    const input = el().querySelector<HTMLInputElement>(
      '[data-testid="rename-input"]',
    );
    expect(input?.value).toBe('Go');
    input!.value = 'Golang';
    input!.dispatchEvent(new Event('input'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="rename-save"]')
      ?.click();
    await settle();

    const req = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${TAGS_URL}/tag-1`),
    );
    expect(req.request.body).toEqual({ name: 'Golang' });
    req.flush({ data: makeTag({ name: 'Golang' }) });
    await settle();

    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TAGS_URL))
      .flush({ data: [makeTag({ name: 'Golang' })] });
    await settle();

    expect(el().querySelector('[data-testid="tag-row-go"]')?.textContent).toContain(
      'Golang',
    );
  });

  it('should PUT the topic rename to the admin topics endpoint', async () => {
    await flushLists();

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

  it('should POST source and target when a merge is submitted', async () => {
    await flushLists();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="tags-merge-open"]')
      ?.click();
    await settle();

    const source = el().querySelector<HTMLSelectElement>(
      '[data-testid="merge-source"]',
    );
    source!.value = 'tag-1';
    source!.dispatchEvent(new Event('change'));
    const target = el().querySelector<HTMLSelectElement>(
      '[data-testid="merge-target"]',
    );
    target!.value = 'tag-2';
    target!.dispatchEvent(new Event('change'));
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="merge-submit"]')
      ?.click();
    await settle();

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(`${TAGS_URL}/merge`),
    );
    expect(req.request.body).toEqual({
      source_id: 'tag-1',
      target_id: 'tag-2',
    });
    req.flush({ data: { aliases_moved: 2, content_tags_moved: 5 } });
    await settle();

    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TAGS_URL))
      .flush({ data: [makeTag({ id: 'tag-2', slug: 'pg', name: 'Postgres' })] });
    await settle();

    expect(el().querySelector('[data-testid="merge-source"]')).toBeNull();
  });

  it('should disable the merge submit while source equals target', async () => {
    await flushLists();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="tags-merge-open"]')
      ?.click();
    await settle();

    for (const testid of ['merge-source', 'merge-target']) {
      const select = el().querySelector<HTMLSelectElement>(
        `[data-testid="${testid}"]`,
      );
      select!.value = 'tag-1';
      select!.dispatchEvent(new Event('change'));
    }
    await settle();

    expect(
      el().querySelector<HTMLButtonElement>('[data-testid="merge-submit"]')
        ?.disabled,
    ).toBe(true);
    expect(
      el().querySelector('[data-testid="merge-same-error"]'),
    ).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="merge-cancel"]')
      ?.click();
    await settle();
  });

  it('should show the tags error state when the tags endpoint fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TAGS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'failed' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TOPICS_URL))
      .flush({ data: [makeTopic()] });
    await settle();

    expect(el().querySelector('[data-testid="tags-error"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="topic-row-system-design"]'),
    ).toBeTruthy();
  });
});
