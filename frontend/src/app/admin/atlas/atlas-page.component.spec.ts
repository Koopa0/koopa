import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AtlasPageComponent } from './atlas-page.component';

describe('AtlasPageComponent', () => {
  it('should create the placeholder', () => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideNoopAnimations()],
    });
    const fixture = TestBed.createComponent(AtlasPageComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance).toBeTruthy();
    expect(fixture.nativeElement.textContent).toContain(
      'Faceted entity search',
    );
  });
});
