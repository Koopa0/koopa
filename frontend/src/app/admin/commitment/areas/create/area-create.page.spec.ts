import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { AreaCreatePageComponent } from './area-create.page';
import { NotificationService } from '../../../../core/services/notification.service';

const AREAS_URL = '/api/admin/commitment/areas';

describe('AreaCreatePageComponent', () => {
  let fixture: ComponentFixture<AreaCreatePageComponent>;
  let httpMock: HttpTestingController;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AreaCreatePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    // No resource reads on init — the create page fetches nothing.
    fixture = TestBed.createComponent(AreaCreatePageComponent);
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => {
    httpMock.verify();
    vi.restoreAllMocks();
    TestBed.resetTestingModule();
  });

  function testid(id: string): HTMLElement | null {
    return el.querySelector(`[data-testid="${id}"]`);
  }

  function submitBtn(): HTMLButtonElement {
    return testid('area-create-submit') as HTMLButtonElement;
  }

  function nameInput(): HTMLInputElement {
    return el.querySelector('#area-name') as HTMLInputElement;
  }

  function descInput(): HTMLTextAreaElement {
    return el.querySelector('#area-desc') as HTMLTextAreaElement;
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function typeName(value: string): Promise<void> {
    const input = nameInput();
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await settle();
  }

  async function typeDesc(value: string): Promise<void> {
    const input = descInput();
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await settle();
  }

  it('should keep submit enabled before the first attempt and show the banner after an invalid submit', async () => {
    expect(submitBtn().disabled).toBe(false);
    expect(testid('area-create-banner')).toBeNull();

    submitBtn().click();
    await settle();

    expect(testid('area-create-banner')?.textContent).toContain(
      'Some fields need attention',
    );
    expect(submitBtn().disabled).toBe(true);
    const toasts = TestBed.inject(NotificationService).notifications();
    expect(toasts.some((n) => n.message === 'Fix the highlighted fields')).toBe(
      true,
    );
    // Blank name → no POST is issued.
    httpMock.expectNone((r) => r.url.endsWith(AREAS_URL));
  });

  it('should preview the slug derived from the name', async () => {
    await typeName('Health & Fitness');
    expect(testid('area-slug-preview')?.textContent).toContain(
      'health-fitness',
    );
  });

  it('should POST name + description with NO slug field and navigate back to the list', async () => {
    await typeName('  Health & Fitness  ');
    await typeDesc('  staying alive  ');
    submitBtn().click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.endsWith(AREAS_URL));
    expect(req.request.method).toBe('POST');
    expect(req.request.url.endsWith(AREAS_URL)).toBe(true);
    // Body carries only name + description — slug is server-derived.
    expect(req.request.body).toEqual({
      name: 'Health & Fitness',
      description: 'staying alive',
    });
    expect(req.request.body).not.toHaveProperty('slug');
    req.flush({
      data: {
        id: 'a_new',
        slug: 'health-fitness',
        name: 'Health & Fitness',
        description: 'staying alive',
        status: 'active',
        sort_order: 3,
        created_at: '2026-06-21T00:00:00Z',
        updated_at: '2026-06-21T00:00:00Z',
      },
    });
    await settle();

    const toasts = TestBed.inject(NotificationService).notifications();
    expect(toasts.some((n) => n.message === 'Area created')).toBe(true);
    expect(navigateSpy).toHaveBeenCalledWith(['/admin/commitment/areas']);
  });

  it('should block submit when the name produces no slug-able characters', async () => {
    await typeName('   ---   ');
    submitBtn().click();
    await settle();

    httpMock.expectNone((r) => r.url.endsWith(AREAS_URL));
    expect(el.textContent).toContain('the slug is derived from this');
  });

  it('should surface the conflict error and re-enable submit on a 409', async () => {
    await typeName('Career');
    submitBtn().click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(AREAS_URL))
      .flush(
        { error: { code: 'CONFLICT', message: 'duplicate slug' } },
        { status: 409, statusText: 'Conflict' },
      );
    await settle();

    expect(testid('area-create-error')?.textContent).toContain(
      'An area with this slug already exists',
    );
    expect(submitBtn().disabled).toBe(false);
  });

  it('should surface a bad-request error on a 400', async () => {
    await typeName('Career');
    submitBtn().click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(AREAS_URL))
      .flush(
        { error: { code: 'BAD_REQUEST', message: 'bad' } },
        { status: 400, statusText: 'Bad Request' },
      );
    await settle();

    expect(testid('area-create-error')?.textContent).toContain(
      'That name can’t be turned into a slug',
    );
    expect(submitBtn().disabled).toBe(false);
  });
});
