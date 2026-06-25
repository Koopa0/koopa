import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router, type Routes } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { ContentEditorPageComponent } from './content-editor.page';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { ApiContent } from '../../../../core/models/api.model';

const CONTENT_URL = '/api/admin/knowledge/content';
// The editor picker reads the admin all-topics endpoint (empty topics included),
// not the public /api/topics list which hides empty categories.
const TOPICS_URL = '/api/admin/knowledge/topics';

const routes: Routes = [
  {
    path: 'admin/knowledge/content/new',
    component: ContentEditorPageComponent,
  },
  {
    path: 'admin/knowledge/content/:id/edit',
    component: ContentEditorPageComponent,
  },
];

function contentPayload(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'abc-1',
    slug: 'value-semantics',
    title: 'Value semantics in Go',
    body: '# Heading\n\nSome body text here.',
    excerpt: 'An excerpt.',
    type: 'article',
    status: 'draft',
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: false,
    ai_metadata: null,
    reading_time_min: 3,
    published_at: null,
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-06-02T00:00:00Z',
    ...overrides,
  };
}

describe('ContentEditorPageComponent', () => {
  let harness: RouterTestingHarness;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter(routes),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return harness.routeNativeElement as HTMLElement;
  }

  async function settle(): Promise<void> {
    harness.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    harness.detectChanges();
  }

  function flushTopics(): void {
    httpMock
      .expectOne((r) => r.url.endsWith(TOPICS_URL))
      .flush({
        data: [
          {
            id: 't1',
            slug: 'go',
            name: 'Go',
            description: '',
            icon: '',
            content_count: 0,
            sort_order: 0,
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z',
          },
        ],
      });
  }

  function setValue(selector: string, value: string): void {
    const input = el().querySelector<HTMLInputElement | HTMLTextAreaElement>(
      selector,
    );
    expect(input).toBeTruthy();
    input!.value = value;
    input!.dispatchEvent(new Event('input'));
  }

  describe('create mode', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/content/new',
      );
      await settle();
      flushTopics();
      await settle();
    });

    it('should render an empty form with slug input and no lifecycle rail', () => {
      expect(el().querySelector('[data-testid="content-editor"]')).toBeTruthy();
      expect(
        el().querySelector('[data-testid="editor-slug-input"]'),
      ).toBeTruthy();
      expect(el().querySelector('[data-testid="editor-lifecycle"]')).toBeNull();
      expect(el().querySelector('[data-testid="editor-is-public"]')).toBeNull();
      expect(
        el().querySelector('[data-testid="editor-create-hint"]')?.textContent,
      ).toContain('not created yet');
    });

    it('should POST the new content and navigate to its edit route on submit', async () => {
      setValue('[data-testid="editor-slug-input"]', 'my-new-post');
      setValue('[data-testid="editor-title"]', 'My new post');
      setValue('[data-testid="editor-body"]', 'Hello world');
      await settle();

      el()
        .querySelector<HTMLFormElement>('[data-testid="content-editor"]')
        ?.dispatchEvent(new Event('submit'));
      await settle();

      const req = httpMock.expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(CONTENT_URL),
      );
      expect(req.request.body).toMatchObject({
        slug: 'my-new-post',
        title: 'My new post',
        type: 'article',
        body: 'Hello world',
      });
      req.flush({
        data: contentPayload({ id: 'created-9', slug: 'my-new-post' }),
      });
      await settle();

      expect(TestBed.inject(Router).url).toBe(
        '/admin/knowledge/content/created-9/edit',
      );
      // The edit route instance loads the created record and topics.
      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/created-9`))
        .flush({ data: contentPayload({ id: 'created-9' }) });
      flushTopics();
      await settle();
    });

    it('should not expose a preview action in create mode', () => {
      const actions =
        TestBed.inject(AdminTopbarService).context().actions ?? [];
      expect(actions.find((a) => a.id === 'preview')).toBeUndefined();
    });

    it('should not POST when required fields are missing', async () => {
      el()
        .querySelector<HTMLFormElement>('[data-testid="content-editor"]')
        ?.dispatchEvent(new Event('submit'));
      await settle();

      httpMock.expectNone(
        (r) => r.method === 'POST' && r.url.endsWith(CONTENT_URL),
      );
    });

    it('should auto-derive the slug from the title until it is edited', async () => {
      setValue('[data-testid="editor-title"]', 'My First Post!');
      await settle();

      const slug = el().querySelector<HTMLInputElement>(
        '[data-testid="editor-slug-input"]',
      );
      expect(slug?.value).toBe('my-first-post');
    });
  });

  describe('edit mode', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/content/abc-1/edit',
      );
      await settle();
      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({ data: contentPayload() });
      flushTopics();
      await settle();
    });

    it('should render the lifecycle rail with the draft transition', () => {
      expect(
        el().querySelector('[data-testid="editor-lifecycle"]'),
      ).toBeTruthy();
      expect(
        el().querySelector(
          '[data-testid="lifecycle-action-submit-for-review"]',
        ),
      ).toBeTruthy();
      expect(el().querySelector('[data-testid="editor-slug-input"]')).toBeNull();
      expect(
        el().querySelector('[data-testid="editor-slug"]')?.textContent,
      ).toContain('value-semantics');
    });

    it('should POST submit-for-review and reload when the rail action is clicked', async () => {
      el()
        .querySelector<HTMLButtonElement>(
          '[data-testid="lifecycle-action-submit-for-review"]',
        )
        ?.click();
      await settle();

      httpMock
        .expectOne(
          (r) =>
            r.method === 'POST' &&
            r.url.endsWith(`${CONTENT_URL}/abc-1/submit-for-review`),
        )
        .flush({ data: contentPayload({ status: 'review' }) });
      await settle();

      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({ data: contentPayload({ status: 'review' }) });
      await settle();

      expect(
        el().querySelector('[data-testid="lifecycle-action-publish"]'),
      ).toBeTruthy();
      expect(
        el().querySelector('[data-testid="lifecycle-publish-gate"]')
          ?.textContent,
      ).toContain('human only');
    });

    it('should open the preview overlay with the /preview/:slug iframe via the topbar action', async () => {
      const topbar = TestBed.inject(AdminTopbarService);
      const previewAction = topbar
        .context()
        .actions?.find((a) => a.id === 'preview');
      expect(previewAction).toBeTruthy();

      previewAction!.run();
      await settle();

      const iframe = el().querySelector<HTMLIFrameElement>(
        '[data-testid="preview-iframe"]',
      );
      expect(iframe?.getAttribute('src')).toBe('/preview/value-semantics');
      expect(
        el().querySelector('[data-testid="preview-note"]')?.textContent,
      ).toContain('draft preview');
    });

    it('should close the preview overlay on scrim mousedown', async () => {
      TestBed.inject(AdminTopbarService)
        .context()
        .actions?.find((a) => a.id === 'preview')
        ?.run();
      await settle();
      expect(
        el().querySelector('[data-testid="preview-scrim"]'),
      ).toBeTruthy();

      el()
        .querySelector<HTMLElement>('[data-testid="preview-scrim"]')
        ?.dispatchEvent(new MouseEvent('mousedown'));
      await settle();

      expect(el().querySelector('[data-testid="preview-scrim"]')).toBeNull();
    });

    it('should close the preview overlay on Escape', async () => {
      TestBed.inject(AdminTopbarService)
        .context()
        .actions?.find((a) => a.id === 'preview')
        ?.run();
      await settle();

      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
      );
      await settle();

      expect(el().querySelector('[data-testid="preview-scrim"]')).toBeNull();
    });

    it('should PATCH is-public when the visibility switch is toggled', async () => {
      el()
        .querySelector<HTMLButtonElement>('[data-testid="editor-is-public"]')
        ?.click();
      await settle();

      const req = httpMock.expectOne(
        (r) =>
          r.method === 'PATCH' &&
          r.url.endsWith(`${CONTENT_URL}/abc-1/is-public`),
      );
      expect(req.request.body).toEqual({ is_public: true });
      req.flush({ data: contentPayload({ is_public: true }) });
      await settle();

      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({ data: contentPayload({ is_public: true }) });
      await settle();

      expect(
        el()
          .querySelector('[data-testid="editor-is-public"]')
          ?.getAttribute('aria-checked'),
      ).toBe('true');
    });

  });

  describe('send-back flow (status=review)', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/content/abc-1/edit',
      );
      await settle();
      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({ data: contentPayload({ status: 'review' }) });
      flushTopics();
      await settle();
    });

    it('should open the send-back dialog when the "Send back" rail action is clicked', async () => {
      el()
        .querySelector<HTMLButtonElement>(
          '[data-testid="lifecycle-action-send-back"]',
        )
        ?.click();
      await settle();

      expect(
        el().querySelector('[data-testid="send-back-reason-textarea"]'),
      ).toBeTruthy();
    });

    it('should POST send-back with the review note and reload on confirm', async () => {
      // Open dialog.
      el()
        .querySelector<HTMLButtonElement>(
          '[data-testid="lifecycle-action-send-back"]',
        )
        ?.click();
      await settle();

      // Type a reason into the textarea.
      const textarea = el().querySelector<HTMLTextAreaElement>(
        '[data-testid="send-back-reason-textarea"]',
      )!;
      textarea.value = 'Please expand the introduction with more context.';
      textarea.dispatchEvent(new Event('input'));
      await settle();

      // Click submit.
      el()
        .querySelector<HTMLButtonElement>('[data-testid="send-back-submit"]')
        ?.click();
      await settle();

      const req = httpMock.expectOne(
        (r) =>
          r.method === 'POST' &&
          r.url.endsWith(`${CONTENT_URL}/abc-1/send-back`),
      );
      expect(req.request.body).toEqual({
        review_note: 'Please expand the introduction with more context.',
      });
      req.flush({
        data: contentPayload({
          status: 'changes_requested',
          review_note: 'Please expand the introduction with more context.',
        }),
      });
      await settle();

      // Resource reload.
      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({
          data: contentPayload({
            status: 'changes_requested',
            review_note: 'Please expand the introduction with more context.',
          }),
        });
      await settle();

      // Dialog should be closed.
      expect(
        el().querySelector('[data-testid="send-back-reason-textarea"]'),
      ).toBeNull();
    });

    it('should close the send-back dialog without a request when cancel is clicked', async () => {
      el()
        .querySelector<HTMLButtonElement>(
          '[data-testid="lifecycle-action-send-back"]',
        )
        ?.click();
      await settle();

      el()
        .querySelector<HTMLButtonElement>('[data-testid="send-back-cancel"]')
        ?.click();
      await settle();

      expect(
        el().querySelector('[data-testid="send-back-reason-textarea"]'),
      ).toBeNull();
      httpMock.expectNone((r) => r.url.includes('send-back'));
    });
  });

  describe('changes_requested display', () => {
    beforeEach(async () => {
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/content/abc-1/edit',
      );
      await settle();
      httpMock
        .expectOne((r) => r.url.endsWith(`${CONTENT_URL}/abc-1`))
        .flush({
          data: contentPayload({
            status: 'changes_requested',
            review_note: 'Add more examples.',
          }),
        });
      flushTopics();
      await settle();
    });

    it('should display the review note when status is changes_requested', () => {
      expect(
        el().querySelector('[data-testid="editor-review-note"]')?.textContent,
      ).toContain('Add more examples.');
    });
  });

  describe('topics resource error', () => {
    it('should fall back to the no-topics notice without throwing when the topics read fails', async () => {
      // The Topics fieldset reads from a secondary resource. A failed read
      // must leave topics() as [] via the hasValue() guard (not throw a
      // ResourceValueError) so the "No topics available" notice renders and
      // the editor form stays usable.
      harness = await RouterTestingHarness.create(
        '/admin/knowledge/content/new',
      );
      await settle();
      httpMock
        .expectOne((r) => r.url.endsWith(TOPICS_URL))
        .flush(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500, statusText: 'Server Error' },
        );
      await settle();

      expect(el().querySelector('[data-testid="content-editor"]')).toBeTruthy();
      expect(
        el().querySelector('[data-testid="editor-topics-empty"]'),
      ).toBeTruthy();
    });
  });
});
