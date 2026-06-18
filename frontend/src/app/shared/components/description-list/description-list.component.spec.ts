import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  DescriptionListComponent,
  type DescriptionRow,
} from './description-list.component';

const ROWS: DescriptionRow[] = [
  { term: 'Name', desc: 'Alice' },
  { term: 'Role', desc: 'Admin' },
  { term: 'Status', desc: 'Active' },
];

describe('DescriptionListComponent', () => {
  let fixture: ComponentFixture<DescriptionListComponent>;
  let component: DescriptionListComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DescriptionListComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(DescriptionListComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render the data-testid="description-list" container', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const dl = fixture.nativeElement.querySelector(
      '[data-testid="description-list"]',
    );
    expect(dl).toBeTruthy();
    expect(dl.tagName.toLowerCase()).toBe('dl');
  });

  it('should render every term when rows are provided', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const terms = fixture.nativeElement.querySelectorAll('dt');
    const termTexts = Array.from(terms).map((t) =>
      (t as HTMLElement).textContent?.trim(),
    );
    expect(termTexts).toContain('Name');
    expect(termTexts).toContain('Role');
    expect(termTexts).toContain('Status');
  });

  it('should render every description when rows are provided', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const descs = fixture.nativeElement.querySelectorAll('dd');
    const descTexts = Array.from(descs).map((d) =>
      (d as HTMLElement).textContent?.trim(),
    );
    expect(descTexts).toContain('Alice');
    expect(descTexts).toContain('Admin');
    expect(descTexts).toContain('Active');
  });

  it('should render exactly as many term/description pairs as rows', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const terms = fixture.nativeElement.querySelectorAll('dt');
    const descs = fixture.nativeElement.querySelectorAll('dd');
    expect(terms.length).toBe(ROWS.length);
    expect(descs.length).toBe(ROWS.length);
  });

  it('should apply standard (non-inline) grid layout by default', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();
    const dl = fixture.nativeElement.querySelector(
      '[data-testid="description-list"]',
    );
    // Default mode wraps each pair in a div; inline does not.
    const wrapperDivs = dl.querySelectorAll('div');
    expect(wrapperDivs.length).toBe(ROWS.length);
  });

  it('should NOT wrap pairs in divs when inline is true', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.componentRef.setInput('inline', true);
    fixture.detectChanges();
    const dl = fixture.nativeElement.querySelector(
      '[data-testid="description-list"]',
    );
    const wrapperDivs = dl.querySelectorAll('div');
    expect(wrapperDivs.length).toBe(0);
  });

  it('should apply inline grid class when inline is true', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.componentRef.setInput('inline', true);
    fixture.detectChanges();
    const dl = fixture.nativeElement.querySelector(
      '[data-testid="description-list"]',
    ) as HTMLElement;
    expect(dl.className).toContain('grid-cols-[max-content_1fr]');
  });

  it('should render an empty list when rows is an empty array', () => {
    fixture.componentRef.setInput('rows', []);
    fixture.detectChanges();
    const terms = fixture.nativeElement.querySelectorAll('dt');
    expect(terms.length).toBe(0);
  });

  it('should update rendered rows when the rows input changes', () => {
    fixture.componentRef.setInput('rows', ROWS);
    fixture.detectChanges();

    const newRows: DescriptionRow[] = [{ term: 'Updated', desc: 'Value' }];
    fixture.componentRef.setInput('rows', newRows);
    fixture.detectChanges();

    const terms = fixture.nativeElement.querySelectorAll('dt');
    expect(terms.length).toBe(1);
    expect((terms[0] as HTMLElement).textContent?.trim()).toBe('Updated');
  });
});
