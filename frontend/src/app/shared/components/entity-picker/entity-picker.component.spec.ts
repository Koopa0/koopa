import { Component, inject, signal } from '@angular/core';
import { HttpClient, provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { map, type Observable } from 'rxjs';

import {
  EntityPickerComponent,
  type PickerEntity,
} from './entity-picker.component';

const SEARCH_URL = '/api/test/search';

interface SearchEnvelope {
  data: { id: string; name: string; domain: string }[];
}

/**
 * Host that two-way binds the picker's selected set and supplies a search
 * function hitting a fake HTTP endpoint — exercises the real rxResource +
 * HTTP boundary, mocking only HTTP.
 */
@Component({
  template: `
    <app-entity-picker
      [search]="search"
      [(selected)]="selected"
      label="Concepts"
      inputId="test-picker"
    />
  `,
  imports: [EntityPickerComponent],
})
class HostComponent {
  private readonly http = inject(HttpClient);
  readonly selected = signal<PickerEntity[]>([]);

  readonly search = (q: string): Observable<PickerEntity[]> =>
    this.http
      .get<SearchEnvelope>(SEARCH_URL, { params: { q } })
      .pipe(
        map((res) =>
          res.data.map((c) => ({
            id: c.id,
            label: c.name,
            sublabel: c.domain,
          })),
        ),
      );
}

describe('EntityPickerComponent', () => {
  let fixture: ComponentFixture<HostComponent>;
  let host: HostComponent;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    fixture = TestBed.createComponent(HostComponent);
    host = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector<HTMLElement>(`[data-testid="${id}"]`);
  }

  /** Waits out the input debounce, then settles change detection. */
  async function settleDebounce(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 300));
    fixture.detectChanges();
  }

  /** Lets a flushed response propagate into the resource, then renders. */
  async function settle(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function type(value: string): void {
    const input = testid('entity-picker-search-input') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }

  function flushSearch(
    data: { id: string; name: string; domain: string }[],
  ): void {
    httpMock
      .expectOne((r) => r.url === SEARCH_URL)
      .flush({ data } satisfies SearchEnvelope);
  }

  it('should render the search input and no dropdown when idle', () => {
    expect(testid('entity-picker')).toBeTruthy();
    expect(testid('entity-picker-search-input')).toBeTruthy();
    expect(testid('entity-picker-results-list')).toBeNull();
  });

  it('should render matching results when the query resolves', async () => {
    type('arr');
    await settleDebounce();
    flushSearch([
      { id: 'c-1', name: 'Arrays', domain: 'dsa' },
      { id: 'c-2', name: 'Array slicing', domain: 'go' },
    ]);
    await settle();

    const list = testid('entity-picker-results-list');
    expect(list).toBeTruthy();
    expect(testid('entity-picker-result-c-1')?.textContent).toContain('Arrays');
    expect(testid('entity-picker-result-c-2')?.textContent).toContain('go');
  });

  it('should add a chip and emit the model when a result is clicked', async () => {
    type('arr');
    await settleDebounce();
    flushSearch([{ id: 'c-1', name: 'Arrays', domain: 'dsa' }]);
    await settle();

    (testid('entity-picker-result-c-1') as HTMLButtonElement).click();
    await settle();

    expect(host.selected().map((e) => e.id)).toEqual(['c-1']);
    expect(testid('entity-picker-chip-c-1')?.textContent).toContain('Arrays');
  });

  it('should append to a pre-populated selection when a result is clicked', async () => {
    host.selected.set([{ id: 'c-1', label: 'Arrays', sublabel: 'dsa' }]);
    await settle();

    type('hash');
    await settleDebounce();
    flushSearch([{ id: 'c-2', name: 'Hashing', domain: 'dsa' }]);
    await settle();

    (testid('entity-picker-result-c-2') as HTMLButtonElement).click();
    await settle();

    expect(host.selected().map((e) => e.id)).toEqual(['c-1', 'c-2']);
  });

  it('should not re-offer an already-selected entity in results', async () => {
    host.selected.set([{ id: 'c-1', label: 'Arrays', sublabel: 'dsa' }]);
    await settle();

    type('arr');
    await settleDebounce();
    flushSearch([
      { id: 'c-1', name: 'Arrays', domain: 'dsa' },
      { id: 'c-2', name: 'Array slicing', domain: 'go' },
    ]);
    await settle();

    expect(testid('entity-picker-result-c-1')).toBeNull();
    expect(testid('entity-picker-result-c-2')).toBeTruthy();
  });

  it('should remove a chip and emit the model when its remove button is clicked', async () => {
    host.selected.set([
      { id: 'c-1', label: 'Arrays', sublabel: 'dsa' },
      { id: 'c-2', label: 'Hashing', sublabel: 'dsa' },
    ]);
    await settle();

    (testid('entity-picker-chip-remove-c-1') as HTMLButtonElement).click();
    await settle();

    expect(host.selected().map((e) => e.id)).toEqual(['c-2']);
    expect(testid('entity-picker-chip-c-1')).toBeNull();
    expect(testid('entity-picker-chip-c-2')).toBeTruthy();
  });

  it('should show an empty state when the query resolves with no matches', async () => {
    type('zzz');
    await settleDebounce();
    flushSearch([]);
    await settle();

    expect(testid('entity-picker-empty')).toBeTruthy();
    expect(testid('entity-picker-results-list')).toBeNull();
  });

  it('should show an error state when the search request fails', async () => {
    type('arr');
    await settleDebounce();
    httpMock
      .expectOne((r) => r.url === SEARCH_URL)
      .flush('boom', { status: 500, statusText: 'Server Error' });
    await settle();

    expect(testid('entity-picker-error')).toBeTruthy();
  });
});
