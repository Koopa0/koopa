import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { UsesComponent } from './uses';
import { SeoService } from '../../core/services/seo/seo.service';

describe('UsesComponent', () => {
  let component: UsesComponent;
  let fixture: ComponentFixture<UsesComponent>;
  let seoService: SeoService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UsesComponent],
      providers: [provideRouter([]), provideNoopAnimations()],
    }).compileComponents();

    seoService = TestBed.inject(SeoService);
    vi.spyOn(seoService, 'updateMeta');
    fixture = TestBed.createComponent(UsesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should call SeoService.updateMeta on init', () => {
    expect(seoService.updateMeta).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Uses' }),
    );
  });
});
