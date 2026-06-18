import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TabItem, TabsComponent } from './tabs.component';

const SAMPLE_TABS: readonly TabItem[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'settings', label: 'Settings' },
  { id: 'billing', label: 'Billing', disabled: true },
];

@Component({
  template: ` <app-tabs [items]="items()" [(active)]="activeId" /> `,
  imports: [TabsComponent],
})
class HostComponent {
  readonly items = signal<readonly TabItem[]>(SAMPLE_TABS);
  readonly activeId = signal('overview');
}

describe('TabsComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;

  function tabBtn(id: string): HTMLButtonElement {
    return fixture.nativeElement.querySelector(
      `[data-testid="tab-${id}"]`,
    ) as HTMLButtonElement;
  }

  function allTabBtns(): NodeListOf<HTMLButtonElement> {
    return fixture.nativeElement.querySelectorAll('[role="tab"]');
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HostComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(
      fixture.nativeElement.querySelector('[role="tablist"]'),
    ).toBeTruthy();
  });

  it('should render a tab button for each item', () => {
    expect(allTabBtns().length).toBe(3);
  });

  it('should render tab labels from items input', () => {
    expect(tabBtn('overview').textContent?.trim()).toBe('Overview');
    expect(tabBtn('settings').textContent?.trim()).toBe('Settings');
    expect(tabBtn('billing').textContent?.trim()).toBe('Billing');
  });

  it('should set aria-selected="true" on the initially active tab', () => {
    expect(tabBtn('overview').getAttribute('aria-selected')).toBe('true');
  });

  it('should set aria-selected="false" on inactive tabs', () => {
    expect(tabBtn('settings').getAttribute('aria-selected')).toBe('false');
  });

  it('should set tabindex="0" on the active tab', () => {
    expect(tabBtn('overview').getAttribute('tabindex')).toBe('0');
  });

  it('should set tabindex="-1" on non-active tabs', () => {
    expect(tabBtn('settings').getAttribute('tabindex')).toBe('-1');
  });

  it('should update active model when an enabled tab is clicked', async () => {
    tabBtn('settings').click();
    await fixture.whenStable();
    expect(host.activeId()).toBe('settings');
  });

  it('should reflect new active tab via aria-selected after click', async () => {
    tabBtn('settings').click();
    await fixture.whenStable();
    expect(tabBtn('settings').getAttribute('aria-selected')).toBe('true');
    expect(tabBtn('overview').getAttribute('aria-selected')).toBe('false');
  });

  it('should not change active when a disabled tab is clicked', async () => {
    tabBtn('billing').click();
    await fixture.whenStable();
    expect(host.activeId()).toBe('overview');
  });

  it('should disable the button element for a disabled tab item', () => {
    expect(tabBtn('billing').disabled).toBe(true);
  });

  it('should not disable button elements for enabled tab items', () => {
    expect(tabBtn('overview').disabled).toBe(false);
    expect(tabBtn('settings').disabled).toBe(false);
  });

  it('should use data-testid="tab-{id}" on each button', () => {
    expect(tabBtn('overview')).toBeTruthy();
    expect(tabBtn('settings')).toBeTruthy();
    expect(tabBtn('billing')).toBeTruthy();
  });

  it('should render tablist with role="tablist" wrapping the buttons', () => {
    const tablist = fixture.nativeElement.querySelector('[role="tablist"]');
    expect(tablist).toBeTruthy();
    const tabs = tablist.querySelectorAll('[role="tab"]');
    expect(tabs.length).toBe(3);
  });

  it('should update aria-selected when active model is changed externally', async () => {
    host.activeId.set('settings');
    await fixture.whenStable();
    expect(tabBtn('settings').getAttribute('aria-selected')).toBe('true');
    expect(tabBtn('overview').getAttribute('aria-selected')).toBe('false');
  });

  it('should render updated tabs when items input changes', async () => {
    host.items.set([
      { id: 'a', label: 'Alpha' },
      { id: 'b', label: 'Beta' },
    ]);
    host.activeId.set('a');
    await fixture.whenStable();
    expect(allTabBtns().length).toBe(2);
    expect(
      fixture.nativeElement
        .querySelector('[data-testid="tab-a"]')
        .textContent?.trim(),
    ).toBe('Alpha');
  });
});
