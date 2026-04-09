import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { TagsComponent } from './tags';
import type { ApiTag, ApiTagAlias } from '../../core/models';

describe('TagsComponent', () => {
  let component: TagsComponent;
  let fixture: ComponentFixture<TagsComponent>;
  let httpTesting: HttpTestingController;

  const MOCK_TAGS: ApiTag[] = [
    {
      id: 'tag-1',
      slug: 'golang',
      name: 'Go',
      parent_id: null,
      description: 'Go programming language',
      created_at: '2026-03-17T00:00:00Z',
      updated_at: '2026-03-17T00:00:00Z',
    },
    {
      id: 'tag-2',
      slug: 'concurrency',
      name: 'Concurrency',
      parent_id: 'tag-1',
      description: '',
      created_at: '2026-03-17T00:00:00Z',
      updated_at: '2026-03-17T00:00:00Z',
    },
  ];

  const MOCK_ALIASES: ApiTagAlias[] = [
    {
      id: 'alias-1',
      raw_tag: 'Go lang',
      tag_id: 'tag-1',
      match_method: 'case_insensitive',
      confirmed: false,
      confirmed_at: null,
      created_at: '2026-03-17T00:00:00Z',
    },
    {
      id: 'alias-2',
      raw_tag: 'unknown-tag',
      tag_id: null,
      match_method: 'unmapped',
      confirmed: false,
      confirmed_at: null,
      created_at: '2026-03-17T00:00:00Z',
    },
  ];

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TagsComponent],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TagsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should load tags on init', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne('/bff/api/admin/tags');
    req.flush({ data: MOCK_TAGS });

    expect(component).toBeTruthy();
  });

  it('should display tags in a table when tags are loaded', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: MOCK_TAGS });
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
  });

  it('should show empty state when no tags exist', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: [] });
    fixture.detectChanges();

    const emptyText = fixture.nativeElement.textContent;
    expect(emptyText).toContain('No tags yet');
  });

  it('should switch to aliases tab when clicking aliases tab', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: MOCK_TAGS });
    fixture.detectChanges();

    component['switchTab']('aliases');
    fixture.detectChanges();

    httpTesting
      .expectOne('/bff/api/admin/aliases')
      .flush({ data: MOCK_ALIASES });
    fixture.detectChanges();

    const cards = fixture.nativeElement.querySelectorAll('.space-y-3 > div');
    expect(cards.length).toBe(2);
  });

  it('should filter unmapped aliases when unmapped filter is selected', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: MOCK_TAGS });

    component['switchTab']('aliases');
    fixture.detectChanges();
    httpTesting
      .expectOne('/bff/api/admin/aliases')
      .flush({ data: MOCK_ALIASES });

    component['setAliasFilter']('unmapped');
    fixture.detectChanges();

    const filtered = component['filteredAliases']();
    expect(filtered.length).toBe(1);
    expect(filtered[0].raw_tag).toBe('unknown-tag');
  });

  it('should filter pending aliases when pending filter is selected', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: MOCK_TAGS });

    component['switchTab']('aliases');
    fixture.detectChanges();
    httpTesting
      .expectOne('/bff/api/admin/aliases')
      .flush({ data: MOCK_ALIASES });

    component['setAliasFilter']('pending');
    fixture.detectChanges();

    const filtered = component['filteredAliases']();
    expect(filtered.length).toBe(1);
    expect(filtered[0].raw_tag).toBe('Go lang');
  });

  it('should handle 409 error when deleting tag with references', () => {
    fixture.detectChanges();
    httpTesting.expectOne('/bff/api/admin/tags').flush({ data: MOCK_TAGS });
    fixture.detectChanges();

    component['requestDeleteTag'](MOCK_TAGS[0]);
    component['confirmDelete']();

    const req = httpTesting.expectOne('/bff/api/admin/tags/tag-1');
    req.flush(
      { error: { code: 'CONFLICT', message: 'has references' } },
      { status: 409, statusText: 'Conflict' },
    );

    fixture.detectChanges();
    // Tag should still exist in the list
    expect(component['tags']().length).toBe(2);
  });
});
