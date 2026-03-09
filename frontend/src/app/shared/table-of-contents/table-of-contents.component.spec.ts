import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { TableOfContentsComponent } from './table-of-contents.component';

describe('TableOfContentsComponent', () => {
  let component: TableOfContentsComponent;
  let fixture: ComponentFixture<TableOfContentsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TableOfContentsComponent],
      providers: [{ provide: PLATFORM_ID, useValue: 'browser' }],
    }).compileComponents();

    fixture = TestBed.createComponent(TableOfContentsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should extract headings from HTML content', () => {
    fixture.componentRef.setInput(
      'content',
      '<h2 id="intro">Introduction</h2><h3 id="setup">Setup</h3>',
    );
    fixture.detectChanges();

    const items = component['tocItems']();
    expect(items.length).toBe(2);
    expect(items[0]).toEqual({ level: 2, id: 'intro', text: 'Introduction' });
    expect(items[1]).toEqual({ level: 3, id: 'setup', text: 'Setup' });
  });

  it('should return empty array when content is empty', () => {
    fixture.componentRef.setInput('content', '');
    fixture.detectChanges();

    expect(component['tocItems']()).toEqual([]);
  });

  it('should strip HTML tags from heading text', () => {
    fixture.componentRef.setInput(
      'content',
      '<h2 id="bold">Hello <strong>World</strong></h2>',
    );
    fixture.detectChanges();

    const items = component['tocItems']();
    expect(items[0].text).toBe('Hello World');
  });

  it('should render nav when headings exist', () => {
    fixture.componentRef.setInput('content', '<h2 id="intro">Intro</h2>');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav).not.toBeNull();
    expect(nav.getAttribute('aria-label')).toBe('Table of contents');
  });

  it('should not render nav when no headings', () => {
    fixture.componentRef.setInput('content', '<p>No headings</p>');
    fixture.detectChanges();

    const nav = fixture.nativeElement.querySelector('nav');
    expect(nav).toBeNull();
  });
});
