import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { GoalCreatePageComponent } from './goal-create.page';
import { NotificationService } from '../../../../core/services/notification.service';

const GOALS_URL = '/api/admin/commitment/goals';

describe('GoalCreatePageComponent', () => {
  let fixture: ComponentFixture<GoalCreatePageComponent>;
  let httpMock: HttpTestingController;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      imports: [GoalCreatePageComponent],
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

    fixture = TestBed.createComponent(GoalCreatePageComponent);
    fixture.detectChanges();
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
    return testid('goal-create-submit') as HTMLButtonElement;
  }

  function titleInput(): HTMLInputElement {
    return el.querySelector('#goal-title') as HTMLInputElement;
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

  it('should keep submit enabled before the first attempt and show the banner after an invalid submit', async () => {
    expect(submitBtn().disabled).toBe(false);
    expect(testid('goal-create-banner')).toBeNull();

    submitBtn().click();
    await settle();

    expect(testid('goal-create-banner')?.textContent).toContain(
      'Some fields need attention',
    );
    expect(submitBtn().disabled).toBe(true);
    const toasts = TestBed.inject(NotificationService).notifications();
    expect(toasts.some((n) => n.message === 'Fix the highlighted fields')).toBe(
      true,
    );
  });

  it('should show the title error after blur when the trimmed title is shorter than 6 characters', async () => {
    await typeTitle('  koo  ');
    titleInput().dispatchEvent(new Event('blur'));
    await settle();

    expect(el.textContent).toContain(
      'Give it at least 6 characters — a real commitment.',
    );
  });

  it('should show the live character count for the title', async () => {
    await typeTitle('Ship koopa');
    expect(testid('goal-title-count')?.textContent).toContain('10/90');
  });

  it('should create the goal with a trimmed title and navigate to its detail', async () => {
    await typeTitle('  Ship koopa v1  ');
    submitBtn().click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.endsWith(GOALS_URL));
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toMatchObject({ title: 'Ship koopa v1' });
    expect(req.request.body).not.toHaveProperty('status');
    req.flush({ data: { id: 'g_new', title: 'Ship koopa v1', status: 'not_started' } });
    await settle();

    const toasts = TestBed.inject(NotificationService).notifications();
    expect(
      toasts.some(
        (n) => n.message === 'Goal created · status set to not_started',
      ),
    ).toBe(true);
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/commitment/goals',
      'g_new',
    ]);
  });

  it('should surface a server error and re-enable submit when creation fails', async () => {
    await typeTitle('Ship koopa v1');
    submitBtn().click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(GOALS_URL))
      .flush(
        { error: { code: 'BAD_REQUEST', message: 'bad' } },
        { status: 400, statusText: 'Bad Request' },
      );
    await settle();

    expect(testid('goal-create-error')?.textContent).toContain(
      'Could not create the goal',
    );
    expect(submitBtn().disabled).toBe(false);
  });
});
