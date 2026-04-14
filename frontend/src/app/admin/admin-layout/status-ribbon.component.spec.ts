import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal, type Signal } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { StatusRibbonComponent } from './status-ribbon.component';
import {
  RibbonService,
  type RibbonTokens,
} from '../../core/services/ribbon.service';

describe('StatusRibbonComponent', () => {
  function setup(state: {
    tokens: RibbonTokens | null;
    loading?: boolean;
    error?: boolean;
  }): ComponentFixture<StatusRibbonComponent> {
    const tokensSignal = signal<RibbonTokens | null>(state.tokens);
    const loadingSignal = signal<boolean>(state.loading ?? false);
    const errorSignal = signal<boolean>(state.error ?? false);

    const ribbonStub = {
      tokens: tokensSignal as Signal<RibbonTokens | null>,
      isLoading: loadingSignal as Signal<boolean>,
      hasError: errorSignal as Signal<boolean>,
    };

    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: RibbonService, useValue: ribbonStub },
      ],
    });
    const fixture = TestBed.createComponent(StatusRibbonComponent);
    fixture.detectChanges();
    return fixture;
  }

  const FRESH_TOKENS: RibbonTokens = {
    pipeline: { label: 'pipeline ok', status: 'ok' },
    feeds: { label: 'feeds 100%', status: 'ok' },
    aiBudget: { label: 'ai 34%', status: 'ok' },
  };

  it('should render brand label even with no tokens', () => {
    const fixture = setup({ tokens: null });
    expect(fixture.nativeElement.textContent).toContain('koopa0 admin');
  });

  it('should render all three tokens when populated', () => {
    const fixture = setup({ tokens: FRESH_TOKENS });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="ribbon-pipeline"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="ribbon-feeds"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="ribbon-ai-budget"]')).toBeTruthy();
    expect(el.textContent).toContain('pipeline ok');
    expect(el.textContent).toContain('feeds 100%');
    expect(el.textContent).toContain('ai 34%');
  });

  it('should apply error color class for error status', () => {
    const fixture = setup({
      tokens: {
        pipeline: { label: 'pipeline 5 failed', status: 'error' },
        feeds: { label: 'feeds 100%', status: 'ok' },
        aiBudget: { label: 'ai 95%', status: 'error' },
      },
    });
    const pipeline = fixture.nativeElement.querySelector(
      '[data-testid="ribbon-pipeline"]',
    ) as HTMLElement;
    const dot = pipeline.querySelector('span') as HTMLElement;
    expect(dot.className).toContain('bg-red-500');
    expect(pipeline.className).toContain('text-red-400');
  });

  it('should show loading state when no tokens and isLoading', () => {
    const fixture = setup({ tokens: null, loading: true });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="ribbon-loading"]')).toBeTruthy();
  });

  it('should show error state when no tokens and hasError', () => {
    const fixture = setup({ tokens: null, error: true });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="ribbon-error"]')).toBeTruthy();
  });

  it('should expose status role and aria-label on the ribbon container', () => {
    const fixture = setup({ tokens: FRESH_TOKENS });
    const ribbon = fixture.nativeElement.querySelector(
      '[data-testid="admin-status-ribbon"]',
    ) as HTMLElement;
    expect(ribbon.getAttribute('role')).toBe('status');
    expect(ribbon.getAttribute('aria-label')).toBe('System status ribbon');
  });
});
