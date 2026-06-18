import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
import {
  ButtonComponent,
  BadgeComponent,
  CalloutComponent,
  AlertComponent,
  TabsComponent,
  type TabItem,
  type BadgeTone,
  type ButtonVariant,
  SegmentedComponent,
  type SegmentedItem,
  BreadcrumbsComponent,
  PaginationComponent,
  NavItemComponent,
  StatCardComponent,
  AvatarComponent,
  AvatarGroupComponent,
  ProgressComponent,
  HextileComponent,
  AccordionComponent,
  AccordionItemComponent,
  DescriptionListComponent,
  StepperComponent,
  SeparatorComponent,
  LoadingSpinnerComponent,
  InputComponent,
  TextareaComponent,
  SelectComponent,
  type SelectOption,
  CheckboxComponent,
  RadioComponent,
  SwitchComponent,
  ChipComponent,
  TagComponent,
  KbdComponent,
  ContentTypeComponent,
  type ContentType,
  MenuComponent,
  MenuItemComponent,
  TooltipDirective,
  DrawerComponent,
  CodeBlockComponent,
} from '../../shared/components';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';

/**
 * Design-system showcase — DS core primitives ingested from the Claude Design
 * "koopa.dev Design System", in their variants. Visual + AXE/WCAG AA
 * verification surface. Route: /design-system.
 *
 * Note: toast and the ⌘K command palette are existing app features
 * (src/app/shared/{toast,command-palette}) and are not re-demoed here; the
 * spinner/skeleton demos use the existing app-loading-spinner / app-skeleton.
 */
@Component({
  selector: 'app-design-system',
  imports: [
    ButtonComponent,
    BadgeComponent,
    CalloutComponent,
    AlertComponent,
    TabsComponent,
    SegmentedComponent,
    BreadcrumbsComponent,
    PaginationComponent,
    NavItemComponent,
    StatCardComponent,
    AvatarComponent,
    AvatarGroupComponent,
    ProgressComponent,
    HextileComponent,
    AccordionComponent,
    AccordionItemComponent,
    DescriptionListComponent,
    StepperComponent,
    SeparatorComponent,
    LoadingSpinnerComponent,
    SkeletonComponent,
    InputComponent,
    TextareaComponent,
    SelectComponent,
    CheckboxComponent,
    RadioComponent,
    SwitchComponent,
    ChipComponent,
    TagComponent,
    KbdComponent,
    ContentTypeComponent,
    MenuComponent,
    MenuItemComponent,
    TooltipDirective,
    DrawerComponent,
    CodeBlockComponent,
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

      <section class="mb-12" aria-labelledby="ds-buttons">
        <h2 id="ds-buttons" class="h3 mb-4">Buttons</h2>
        <div class="flex flex-wrap items-center gap-3">
          @for (v of buttonVariants; track v) {
            <app-button [variant]="v" [testId]="'btn-' + v">{{ v }}</app-button>
          }
          <app-button variant="primary" [loading]="true">saving</app-button>
          <app-button variant="primary" [disabled]="true">disabled</app-button>
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-badges">
        <h2 id="ds-badges" class="h3 mb-4">Badges · content-type</h2>
        <div class="flex flex-wrap items-center gap-2">
          @for (t of badgeTones; track t) {
            <app-badge [tone]="t">{{ t }}</app-badge>
          }
        </div>
        <div class="mt-3 flex flex-wrap items-center gap-3">
          @for (ct of contentTypes; track ct) {
            <app-content-type [type]="ct" />
          }
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-nav">
        <h2 id="ds-nav" class="h3 mb-4">Navigation</h2>
        <app-breadcrumbs [items]="crumbs" />
        <div class="mt-4">
          <app-tabs [items]="tabs" [(active)]="activeTab" />
          <div class="mt-3 text-[13px] text-fg-muted" data-testid="tab-panel">
            Active: <strong class="text-fg">{{ activeTab() }}</strong>
          </div>
        </div>
        <div class="mt-4 flex flex-wrap items-center gap-4">
          <app-segmented
            [items]="ranges"
            [(active)]="range"
            ariaLabel="Range"
          />
          <app-pagination [total]="237" [pageSize]="10" [(page)]="page" />
        </div>
        <div class="mt-4 max-w-xs rounded-md border border-border bg-panel p-2">
          <app-nav-item label="Dashboard" [active]="true" [count]="3" />
          <app-nav-item label="Drafts" [count]="7" />
          <app-nav-item label="Settings" />
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-data">
        <h2 id="ds-data" class="h3 mb-4">Data display</h2>
        <div class="grid gap-4 sm:grid-cols-3">
          <app-stat-card
            label="Published"
            [value]="128"
            delta="+12%"
            trend="up"
          />
          <app-stat-card
            label="In review"
            [value]="6"
            delta="-2"
            trend="down"
          />
          <app-stat-card label="Drafts" [value]="14" trend="flat" />
        </div>
        <div class="mt-4 flex items-center gap-4">
          <app-avatar initials="KP" size="lg" />
          <app-avatar actor="human" initials="H" />
          <app-avatar actor="claude-cowork" initials="C" />
          <app-avatar-group [overflow]="3">
            <app-avatar initials="AB" />
            <app-avatar initials="CD" />
            <app-avatar initials="EF" />
          </app-avatar-group>
          <app-hextile>
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 2l9 5v10l-9 5-9-5V7z" />
            </svg>
          </app-hextile>
        </div>
        <div class="mt-4 max-w-md space-y-3">
          <app-progress [value]="72" />
          <app-progress [value]="48" tone="success" label="Mastery" />
          <app-skeleton variant="text" />
          <app-skeleton variant="card" />
        </div>
        <div class="mt-4 max-w-lg">
          <app-code-block lang="ts" [code]="snippet" testId="cb-demo" />
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-more">
        <h2 id="ds-more" class="h3 mb-4">Disclosure · steps</h2>
        <app-stepper [steps]="steps" [current]="1" />
        <div class="mt-4 max-w-lg">
          <app-accordion>
            <app-accordion-item title="What is this?" [defaultOpen]="true">
              A semantic runtime, not a blog.
            </app-accordion-item>
            <app-accordion-item title="How it works">
              Agents read and write through MCP.
            </app-accordion-item>
          </app-accordion>
        </div>
        <div class="mt-4 max-w-lg">
          <app-description-list [rows]="dlRows" />
        </div>
        <app-separator label="OR" class="my-4 block" />
        <div class="flex items-center gap-3">
          <app-loading-spinner size="sm" />
          <app-loading-spinner size="md" />
          <app-loading-spinner size="lg" />
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-forms">
        <h2 id="ds-forms" class="h3 mb-4">Forms</h2>
        <div class="grid max-w-lg gap-4">
          <app-input [(value)]="name" placeholder="Your name" />
          <app-textarea [(value)]="bio" placeholder="About you" [rows]="3" />
          <app-select
            [(value)]="role"
            [options]="roleOptions"
            placeholder="Pick a role"
          />
          <div class="flex flex-col gap-2">
            <app-checkbox [(checked)]="agree">I accept the terms</app-checkbox>
            <app-radio name="plan" value="free" [(groupValue)]="plan"
              >Free</app-radio
            >
            <app-radio name="plan" value="pro" [(groupValue)]="plan"
              >Pro</app-radio
            >
            <app-switch [(checked)]="notify">Email notifications</app-switch>
          </div>
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-small">
        <h2 id="ds-small" class="h3 mb-4">Inline</h2>
        <div class="flex flex-wrap items-center gap-2">
          <app-chip [active]="true">active</app-chip>
          <app-chip>idle</app-chip>
          <app-chip [removable]="true">removable</app-chip>
          <app-tag href="/t/angular">#angular</app-tag>
          <span class="text-[13px] text-fg-muted">
            Press <app-kbd>⌘</app-kbd> <app-kbd>K</app-kbd>
          </span>
        </div>
      </section>

      <section class="mb-12" aria-labelledby="ds-feedback">
        <h2 id="ds-feedback" class="h3 mb-4">Feedback · overlays</h2>
        <div class="flex flex-col gap-3">
          <app-callout variant="brand" label="Note">
            A system that makes decisions for you eventually makes you worse at
            making decisions yourself.
          </app-callout>
          @for (v of alertVariants; track v) {
            <app-alert [variant]="v" [heading]="v + ': '">
              Inline alert for the {{ v }} state.
            </app-alert>
          }
        </div>
        <div class="mt-4 flex flex-wrap items-center gap-3">
          <app-button appTooltip="I'm a tooltip" variant="secondary"
            >Hover me</app-button
          >
          <app-menu ariaLabel="Actions">
            <app-button menu-trigger variant="secondary">Actions ▾</app-button>
            <app-menu-item>Edit</app-menu-item>
            <app-menu-item variant="danger">Delete</app-menu-item>
          </app-menu>
          <app-button variant="secondary" (click)="drawerOpen.set(true)">
            Open drawer
          </app-button>
        </div>
      </section>

      <app-drawer [(open)]="drawerOpen" labelledBy="drawer-title">
        <h2 drawer-header id="drawer-title" class="h4">Settings</h2>
        <p class="text-[13px] text-fg-muted">Drawer body content.</p>
        <div drawer-footer>
          <app-button variant="secondary" (click)="drawerOpen.set(false)"
            >Close</app-button
          >
        </div>
      </app-drawer>
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
  protected readonly contentTypes: readonly ContentType[] = [
    'article',
    'essay',
    'build-log',
    'til',
    'note',
    'digest',
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

  protected readonly ranges: readonly SegmentedItem[] = [
    { id: 'day', label: 'Day' },
    { id: 'week', label: 'Week' },
    { id: 'month', label: 'Month' },
  ];
  protected readonly range = signal('week');
  protected readonly page = signal(1);
  protected readonly crumbs = [
    { label: 'Home', href: '/' },
    { label: 'Design', href: '/design-system' },
    { label: 'Components' },
  ];

  protected readonly steps = [
    { label: 'Plan' },
    { label: 'Build' },
    { label: 'Ship' },
  ];
  protected readonly dlRows = [
    { term: 'Status', desc: 'Published' },
    { term: 'Type', desc: 'build-log' },
    { term: 'Updated', desc: '2 days ago' },
  ];

  protected readonly name = signal('');
  protected readonly bio = signal('');
  protected readonly role = signal('');
  protected readonly roleOptions: readonly SelectOption[] = [
    { value: 'owner', label: 'Owner' },
    { value: 'editor', label: 'Editor' },
    { value: 'viewer', label: 'Viewer' },
  ];
  protected readonly agree = signal(false);
  protected readonly plan = signal('free');
  protected readonly notify = signal(true);

  protected readonly drawerOpen = signal(false);

  protected readonly snippet = `const x = signal(0);\nconst double = computed(() => x() * 2);`;
}
