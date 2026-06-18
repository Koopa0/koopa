import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';

import { DomainsListPageComponent } from './domains-list.page';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

describe('DomainsListPageComponent', () => {
  let fixture: ComponentFixture<DomainsListPageComponent>;
  let el: HTMLElement;
  const getDomains = vi.fn();

  async function setup(): Promise<void> {
    TestBed.configureTestingModule({
      imports: [DomainsListPageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { getDomains } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });

    fixture = TestBed.createComponent(DomainsListPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    vi.clearAllMocks();
    TestBed.resetTestingModule();
  });

  it('should render a row per domain', async () => {
    getDomains.mockReturnValue(
      of([
        { slug: 'go', name: 'Go' },
        { slug: 'systems-design', name: 'Systems design' },
      ]),
    );
    await setup();

    const rows = el.querySelectorAll('[data-testid^="domains-list-row-"]');
    expect(rows.length).toBe(2);
    expect(el.textContent).toContain('go');
    expect(el.textContent).toContain('Systems design');
    expect(
      el.querySelector('[data-testid="domains-count"]')?.textContent,
    ).toContain('2');
  });

  it('should show the empty state when no domains exist', async () => {
    getDomains.mockReturnValue(of([]));
    await setup();

    expect(el.querySelector('[data-testid="domains-list-table"]')).toBeNull();
    expect(el.textContent).toContain('No domains yet');
    expect(el.textContent).toContain(
      'Create a domain to organise learning plans and concepts.',
    );
  });

  it('should surface the error banner without throwing when the list read fails', async () => {
    // A failed read leaves the resource in an error state; rows() must fall
    // back to [] via the hasValue() guard (not throw a ResourceValueError),
    // and the error banner must render.
    getDomains.mockReturnValue(throwError(() => new Error('boom')));
    await setup();

    expect(
      el.querySelector('[data-testid="domains-list-error"]'),
    ).not.toBeNull();
    expect(el.querySelector('[data-testid="domains-list-table"]')).toBeNull();
  });
});
