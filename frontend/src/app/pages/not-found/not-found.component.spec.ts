import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { NotFoundComponent } from './not-found.component';
import { SeoService } from '../../core/services/seo/seo.service';

describe('NotFoundComponent', () => {
  let component: NotFoundComponent;
  let fixture: ComponentFixture<NotFoundComponent>;
  let seoService: SeoService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NotFoundComponent],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(NotFoundComponent);
    component = fixture.componentInstance;
    seoService = TestBed.inject(SeoService);
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should render 404 text', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement;
    expect(el.textContent).toContain('404');
  });

  it('should render error message', () => {
    fixture.detectChanges();
    const el = fixture.nativeElement;
    expect(el.textContent).toContain('找不到頁面');
  });

  it('should call seoService.updateMeta with noIndex on init', () => {
    spyOn(seoService, 'updateMeta');
    fixture.detectChanges();

    expect(seoService.updateMeta).toHaveBeenCalledWith(
      jasmine.objectContaining({
        title: '404 - 找不到頁面',
        noIndex: true,
      }),
    );
  });

  it('should render navigation links', () => {
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('a');
    expect(links.length).toBe(3);

    const hrefs = Array.from(links).map((a: unknown) =>
      (a as HTMLAnchorElement).getAttribute('href'),
    );
    expect(hrefs).toContain('/home');
    expect(hrefs).toContain('/articles');
    expect(hrefs).toContain('/about');
  });
});
