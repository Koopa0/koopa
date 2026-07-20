import { ComponentFixture, TestBed } from '@angular/core/testing';

import {
  ContentLifecycleRailComponent,
  type ContentLifecycleAction,
} from './lifecycle-rail.component';

describe('ContentLifecycleRailComponent', () => {
  let fixture: ComponentFixture<ContentLifecycleRailComponent>;

  function create(status: string, busy = false, sourceBound?: boolean): void {
    fixture = TestBed.createComponent(ContentLifecycleRailComponent);
    fixture.componentRef.setInput('status', status);
    fixture.componentRef.setInput('busy', busy);
    if (sourceBound !== undefined) {
      fixture.componentRef.setInput('sourceBound', sourceBound);
    }
    fixture.detectChanges();
  }

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ContentLifecycleRailComponent],
    });
  });

  it('should render all five stages with the current one marked when status is draft', () => {
    create('draft');

    const steps = el().querySelectorAll('[data-testid^="lifecycle-step-"]');
    expect(steps.length).toBe(5);
    expect(
      el()
        .querySelector('[data-testid="lifecycle-step-draft"]')
        ?.getAttribute('aria-current'),
    ).toBe('step');
    expect(
      el()
        .querySelector('[data-testid="lifecycle-step-review"]')
        ?.getAttribute('aria-current'),
    ).toBeNull();
  });

  it('should offer Publish and Submit for review when status is draft', () => {
    create('draft');

    const buttons = el().querySelectorAll('[data-testid^="lifecycle-action-"]');
    expect(buttons.length).toBe(2);
    expect(
      el().querySelector('[data-testid="lifecycle-action-publish"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="lifecycle-action-submit-for-review"]'),
    ).toBeTruthy();
    // The human-only gate caption is for a review row, not a draft.
    expect(
      el().querySelector('[data-testid="lifecycle-publish-gate"]'),
    ).toBeNull();
  });

  it('should not offer promotion actions for a legacy source-unbound draft', () => {
    create('draft', false, false);

    expect(
      el().querySelector('[data-testid="lifecycle-action-publish"]'),
    ).toBeNull();
    expect(
      el().querySelector('[data-testid="lifecycle-action-submit-for-review"]'),
    ).toBeNull();
  });

  it('should offer Send back, Revert and Publish plus the human-only gate when status is review', () => {
    create('review');

    expect(
      el().querySelector('[data-testid="lifecycle-action-send-back"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="lifecycle-action-revert-to-draft"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="lifecycle-action-publish"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="lifecycle-publish-gate"]')?.textContent,
    ).toContain('human only');
  });

  it('should include changes_requested step and offer Revert + Archive when in that status', () => {
    create('changes_requested');

    const steps = el().querySelectorAll('[data-testid^="lifecycle-step-"]');
    expect(steps.length).toBe(5);
    expect(
      el()
        .querySelector('[data-testid="lifecycle-step-changes_requested"]')
        ?.getAttribute('aria-current'),
    ).toBe('step');
    expect(
      el().querySelector('[data-testid="lifecycle-action-revert-to-draft"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="lifecycle-action-archive"]'),
    ).toBeTruthy();
    // No publish action for changes_requested.
    expect(
      el().querySelector('[data-testid="lifecycle-action-publish"]'),
    ).toBeNull();
  });

  it('should offer Archive when published and Revert to draft when archived', () => {
    create('published');
    expect(
      el().querySelector('[data-testid="lifecycle-action-archive"]'),
    ).toBeTruthy();

    create('archived');
    expect(
      el().querySelector('[data-testid="lifecycle-action-revert-to-draft"]'),
    ).toBeTruthy();
  });

  it('should emit the action id when a transition button is clicked', () => {
    create('review');
    const emitted: ContentLifecycleAction[] = [];
    fixture.componentInstance.action.subscribe((a) => emitted.push(a));

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="lifecycle-action-publish"]',
      )
      ?.click();

    expect(emitted).toEqual(['publish']);
  });

  it('should disable transition buttons and swallow clicks while busy', () => {
    create('draft', true);
    const emitted: ContentLifecycleAction[] = [];
    fixture.componentInstance.action.subscribe((a) => emitted.push(a));

    const button = el().querySelector<HTMLButtonElement>(
      '[data-testid="lifecycle-action-submit-for-review"]',
    );
    expect(button?.disabled).toBe(true);
    button?.click();
    expect(emitted).toEqual([]);
  });
});
