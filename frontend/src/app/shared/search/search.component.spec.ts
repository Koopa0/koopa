import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { SearchComponent } from './search.component';

describe('SearchComponent', () => {
  let component: SearchComponent;
  let fixture: ComponentFixture<SearchComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SearchComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(SearchComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should start with empty search query', () => {
    expect(component['searchQuery']()).toBe('');
  });

  it('should start with results hidden', () => {
    expect(component['showResults']()).toBe(false);
  });

  it('should update query on input', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = 'Angular';
    input.dispatchEvent(new Event('input'));

    expect(component['searchQuery']()).toBe('Angular');
  });

  it('should show results when query is not empty', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = 'test';
    input.dispatchEvent(new Event('input'));

    expect(component['showResults']()).toBe(true);
  });

  it('should clear search and hide results', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = 'test';
    input.dispatchEvent(new Event('input'));

    component['clearSearch']();

    expect(component['searchQuery']()).toBe('');
    expect(component['showResults']()).toBe(false);
  });

  it('should have search input with aria-label', () => {
    const input = fixture.nativeElement.querySelector('input');
    expect(input.getAttribute('aria-label')).toBe('Search articles');
  });

  it('should have search role on container', () => {
    const container = fixture.nativeElement.querySelector('[role="search"]');
    expect(container).not.toBeNull();
  });
});
