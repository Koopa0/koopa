import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { ProjectCreatePageComponent } from './project-create.page';
import { NotificationService } from '../../../../core/services/notification.service';

const PROJECTS_URL = '/api/admin/commitment/projects';
const GOALS_URL = '/api/admin/commitment/goals';
const AREAS_URL = '/api/admin/commitment/areas';

const goalRows = [
  { id: 'goal-1', title: 'Ship koopa v1', status: 'in_progress' },
  { id: 'goal-2', title: 'Draft the GDE story', status: 'not_started' },
];

const areaRows = [
  { id: 'area-1', slug: 'career', name: 'Career', sort_order: 1 },
  { id: 'area-2', slug: 'health', name: 'Health', sort_order: 2 },
];

describe('ProjectCreatePageComponent', () => {
  let fixture: ComponentFixture<ProjectCreatePageComponent>;
  let httpMock: HttpTestingController;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      imports: [ProjectCreatePageComponent],
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

    fixture = TestBed.createComponent(ProjectCreatePageComponent);
    fixture.detectChanges();
    // Both selector resources (areas + goals) load on init; rxResource
    // resolves on a macrotask, so let the loaders run, then flush each.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(AREAS_URL))
      .flush({ data: areaRows });
    httpMock
      .expectOne((r) => r.url.endsWith(GOALS_URL))
      .flush({ data: goalRows });
    await fixture.whenStable();
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
    return testid('project-create-submit') as HTMLButtonElement;
  }

  function titleInput(): HTMLInputElement {
    return el.querySelector('#project-title') as HTMLInputElement;
  }

  function slugInput(): HTMLInputElement {
    return el.querySelector('#project-slug') as HTMLInputElement;
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function typeTitle(value: string): Promise<void> {
    const input = titleInput();
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await settle();
  }

  async function typeSlug(value: string): Promise<void> {
    const input = slugInput();
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await settle();
  }

  it('should keep submit enabled before the first attempt and show the banner after an invalid submit', async () => {
    expect(submitBtn().disabled).toBe(false);
    expect(testid('project-create-banner')).toBeNull();

    submitBtn().click();
    await settle();

    expect(testid('project-create-banner')?.textContent).toContain(
      'Some fields need attention',
    );
    expect(submitBtn().disabled).toBe(true);
    const toasts = TestBed.inject(NotificationService).notifications();
    expect(toasts.some((n) => n.message === 'Fix the highlighted fields')).toBe(
      true,
    );
  });

  it('should auto-suggest a slug from the title until the slug is edited by hand', async () => {
    await typeTitle('Personal Knowledge Engine');
    expect(slugInput().value).toBe('personal-knowledge-engine');

    // Manually edit the slug, then change the title — the slug stays put.
    await typeSlug('my-engine');
    await typeTitle('Something Completely Different');
    expect(slugInput().value).toBe('my-engine');
  });

  it('should create the project with explicit slug + trimmed title and navigate to its detail', async () => {
    await typeTitle('  Knowledge engine  ');
    await typeSlug('knowledge-engine');
    submitBtn().click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.endsWith(PROJECTS_URL));
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toMatchObject({
      title: 'Knowledge engine',
      slug: 'knowledge-engine',
    });
    expect(req.request.body).not.toHaveProperty('status');
    // No area / goal picked → those keys are omitted (server NULLs them).
    expect(req.request.body).not.toHaveProperty('area_id');
    expect(req.request.body).not.toHaveProperty('goal_id');
    req.flush({
      data: { id: 'p_new', slug: 'knowledge-engine', title: 'Knowledge engine', status: 'in_progress' },
    });
    await settle();

    const toasts = TestBed.inject(NotificationService).notifications();
    expect(
      toasts.some(
        (n) => n.message === 'Project created · status set to in_progress',
      ),
    ).toBe(true);
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/commitment/projects',
      'p_new',
    ]);
  });

  it('should send area_id when an area is picked', async () => {
    await typeTitle('Knowledge engine');
    const select = el.querySelector('#project-area') as HTMLSelectElement;
    // "No area" placeholder plus one option per area row.
    expect(select.options.length).toBe(areaRows.length + 1);
    expect(select.textContent).toContain('Career');
    select.value = 'area-2';
    select.dispatchEvent(new Event('change'));
    select.dispatchEvent(new Event('input'));
    await settle();

    submitBtn().click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.endsWith(PROJECTS_URL));
    expect(req.request.body).toMatchObject({ area_id: 'area-2' });
    req.flush({
      data: { id: 'p_area', slug: 'knowledge-engine', title: 'Knowledge engine', status: 'in_progress' },
    });
    await settle();
  });

  it('should send goal_id when a goal is picked', async () => {
    await typeTitle('Knowledge engine');
    const select = el.querySelector('#project-goal') as HTMLSelectElement;
    // "No goal" placeholder plus one option per goal row.
    expect(select.options.length).toBe(goalRows.length + 1);
    select.value = 'goal-2';
    select.dispatchEvent(new Event('change'));
    select.dispatchEvent(new Event('input'));
    await settle();

    submitBtn().click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.endsWith(PROJECTS_URL));
    expect(req.request.body).toMatchObject({ goal_id: 'goal-2' });
    expect(req.request.body).not.toHaveProperty('area_id');
    req.flush({
      data: { id: 'p_goal', slug: 'knowledge-engine', title: 'Knowledge engine', status: 'in_progress' },
    });
    await settle();
  });

  it('should block submit when the required slug is cleared', async () => {
    await typeTitle('Knowledge engine');
    await typeSlug('');
    submitBtn().click();
    await settle();

    // Invalid → no POST is issued, banner shows instead.
    httpMock.expectNone((r) => r.url.endsWith(PROJECTS_URL));
    expect(testid('project-create-banner')).not.toBeNull();
  });

  it('should surface a slug-conflict message and re-enable submit on a 409', async () => {
    await typeTitle('Knowledge engine');
    await typeSlug('knowledge-engine');
    submitBtn().click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(PROJECTS_URL))
      .flush(
        { error: { code: 'CONFLICT', message: 'duplicate slug' } },
        { status: 409, statusText: 'Conflict' },
      );
    await settle();

    expect(testid('project-create-error')?.textContent).toContain(
      'That slug is already taken',
    );
    expect(submitBtn().disabled).toBe(false);
  });

  it('should surface a generic server error on a non-409 failure', async () => {
    await typeTitle('Knowledge engine');
    await typeSlug('knowledge-engine');
    submitBtn().click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(PROJECTS_URL))
      .flush(
        { error: { code: 'BAD_REQUEST', message: 'bad' } },
        { status: 400, statusText: 'Bad Request' },
      );
    await settle();

    expect(testid('project-create-error')?.textContent).toContain(
      'Could not create the project',
    );
    expect(submitBtn().disabled).toBe(false);
  });
});
