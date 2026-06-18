import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import {
  ButtonComponent,
  CardComponent,
  BadgeComponent,
  CalloutComponent,
  AlertComponent,
  TabsComponent,
  type TabItem,
  type BadgeTone,
  type ButtonVariant,
} from '../../shared/components';

/**
 * Design-system showcase — renders the DS core primitives ingested from the
 * Claude Design "koopa.dev Design System" project in every variant. Doubles
 * as the visual + AXE/WCAG AA verification surface for the ingest.
 */
@Component({
  selector: 'app-design-system',
  imports: [
    ButtonComponent,
    CardComponent,
    BadgeComponent,
    CalloutComponent,
    AlertComponent,
    TabsComponent,
  ],
  template: `
    <main class="mx-auto max-w-5xl px-6 py-12" data-testid="design-system-page">
      <header class="mb-10">
        <h1 class="h1">Design system</h1>
        <p class="lead mt-2">
          Core primitives ingested from the Claude Design “koopa.dev Design
          System”.
        </p>
      </header>

      <!-- Buttons -->
      <section class="mb-12" aria-labelledby="ds-buttons">
        <h2 id="ds-buttons" class="h3 mb-4">Buttons</h2>
        <div class="flex flex-wrap items-center gap-3">
          @for (v of buttonVariants; track v) {
            <app-button [variant]="v" [testId]="'btn-' + v">{{ v }}</app-button>
          }
          <app-button variant="primary" [loading]="true" testId="btn-loading">
            saving
          </app-button>
          <app-button variant="primary" [disabled]="true" testId="btn-disabled">
            disabled
          </app-button>
        </div>
        <div class="mt-3 flex flex-wrap items-center gap-3">
          <app-button variant="primary" size="xs">xs</app-button>
          <app-button variant="primary" size="sm">sm</app-button>
          <app-button variant="primary" size="md">md</app-button>
          <app-button variant="primary" size="lg">lg</app-button>
        </div>
      </section>

      <!-- Badges -->
      <section class="mb-12" aria-labelledby="ds-badges">
        <h2 id="ds-badges" class="h3 mb-4">Badges</h2>
        <div class="flex flex-wrap items-center gap-2">
          @for (t of badgeTones; track t) {
            <app-badge [tone]="t" [testId]="'badge-' + t">{{ t }}</app-badge>
          }
        </div>
      </section>

      <!-- Cards -->
      <section class="mb-12" aria-labelledby="ds-cards">
        <h2 id="ds-cards" class="h3 mb-4">Cards</h2>
        <div class="grid gap-4 sm:grid-cols-2">
          <app-card
            title="Quiet instrument"
            description="A card with a header, body, and a hairline-separated footer."
            [hoverable]="true"
            testId="card-basic"
          >
            <p class="text-[13px] text-fg-muted">
              Cards rely on border + background, not shadow — per the DS.
            </p>
            <div
              card-footer
              class="mt-3.5 flex gap-2 border-t border-border-faint pt-3.5"
            >
              <app-button variant="primary" size="sm">Confirm</app-button>
              <app-button variant="ghost" size="sm">Cancel</app-button>
            </div>
          </app-card>
          <app-card padding="lg" testId="card-lg">
            <h3 class="font-display text-xl font-semibold text-fg">
              Large card
            </h3>
            <p class="mt-2 text-[13px] text-fg-muted">
              Padding <code class="font-mono">lg</code> uses radius r-lg.
            </p>
          </app-card>
        </div>
      </section>

      <!-- Tabs (interactive) -->
      <section class="mb-12" aria-labelledby="ds-tabs">
        <h2 id="ds-tabs" class="h3 mb-4">Tabs</h2>
        <app-tabs [items]="tabs" [(active)]="activeTab" />
        <div class="mt-4 text-[13px] text-fg-muted" data-testid="tab-panel">
          Active panel: <strong class="text-fg">{{ activeTab() }}</strong>
        </div>
      </section>

      <!-- Callouts -->
      <section class="mb-12" aria-labelledby="ds-callouts">
        <h2 id="ds-callouts" class="h3 mb-4">Callouts</h2>
        <div class="flex flex-col gap-4">
          <app-callout variant="brand" label="Note" testId="callout-brand">
            A system that makes decisions for you eventually makes you worse at
            making decisions yourself.
          </app-callout>
          <app-callout variant="warn" label="Careful" testId="callout-warn">
            auto-carryover is convenient, but it silently erodes your
            relationship with your own commitments.
          </app-callout>
        </div>
      </section>

      <!-- Alerts -->
      <section class="mb-12" aria-labelledby="ds-alerts">
        <h2 id="ds-alerts" class="h3 mb-4">Alerts</h2>
        <div class="flex flex-col gap-3">
          @for (v of alertVariants; track v) {
            <app-alert
              [variant]="v"
              [heading]="v + ': '"
              [testId]="'alert-' + v"
            >
              Inline alert message for the {{ v }} state.
            </app-alert>
          }
        </div>
      </section>
    </main>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DesignSystemComponent {
  protected readonly buttonVariants: readonly ButtonVariant[] = [
    'primary',
    'secondary',
    'ghost',
    'danger',
  ];
  protected readonly badgeTones: readonly BadgeTone[] = [
    'neutral',
    'brand',
    'success',
    'warn',
    'error',
    'info',
  ];
  protected readonly alertVariants = [
    'info',
    'success',
    'warn',
    'error',
  ] as const;

  protected readonly tabs: readonly TabItem[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'tokens', label: 'Tokens' },
    { id: 'components', label: 'Components' },
    { id: 'soon', label: 'Soon', disabled: true },
  ];
  protected readonly activeTab = signal('overview');
}
