import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { TopicsComponent } from './topics';
import type { ApiTopic } from '../../core/models';

function buildMockTopic(overrides: Partial<ApiTopic> = {}): ApiTopic {
  return {
    id: 't-1',
    slug: 'go',
    name: 'Go',
    description: 'Backend work, mostly.',
    icon: '',
    content_count: 7,
    sort_order: 1,
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
    ...overrides,
  };
}

describe('TopicsComponent', () => {
  let fixture: ComponentFixture<TopicsComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TopicsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TopicsComponent);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  /** Flush effects + macrotasks so the rxResource issues its request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushTopics(topics: ApiTopic[]): void {
    httpTesting
      .expectOne((r) => r.url.includes('/api/topics') && r.method === 'GET')
      .flush({ data: topics });
  }

  it('should render the index title', async () => {
    await settle();
    flushTopics([]);
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent,
    ).toContain('By topic.');
  });

  it('should list each topic as a row linking to its page', async () => {
    await settle();
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 7 }),
      buildMockTopic({
        id: 't2',
        slug: 'rust',
        name: 'Rust',
        content_count: 2,
      }),
    ]);
    await settle();

    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll(
      '[data-testid="topic-card"]',
    );
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('Go');
    expect(rows[0].textContent).toContain('7');
    expect(rows[0].getAttribute('href')).toBe('/topics/go');
  });

  it('should show the empty line when there are no topics', async () => {
    await settle();
    flushTopics([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="topic-card"]')).toBeNull();
    expect(el.querySelector('.ed-index-note')?.textContent).toContain(
      'No topics yet',
    );
  });

  it('should surface an error line when the request fails', async () => {
    await settle();
    httpTesting
      .expectOne((r) => r.url.includes('/api/topics') && r.method === 'GET')
      .flush('err', { status: 500, statusText: 'Internal Server Error' });
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="topic-card"]')).toBeNull();
    expect(el.querySelector('.ed-index-note')?.textContent).toContain(
      'Failed to load topics',
    );
  });
});
