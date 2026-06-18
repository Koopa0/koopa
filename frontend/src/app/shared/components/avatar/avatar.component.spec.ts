import { ComponentFixture, TestBed } from '@angular/core/testing';
import { AvatarComponent } from './avatar.component';

describe('AvatarComponent', () => {
  let fixture: ComponentFixture<AvatarComponent>;
  let component: AvatarComponent;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AvatarComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(AvatarComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  describe('image rendering', () => {
    it('should render an img element when src input is provided', () => {
      fixture.componentRef.setInput('src', 'https://example.com/avatar.png');
      fixture.componentRef.setInput('alt', 'Jane Doe');
      fixture.detectChanges();

      const img = fixture.nativeElement.querySelector(
        'img',
      ) as HTMLImageElement;
      expect(img).toBeTruthy();
      expect(img.src).toContain('https://example.com/avatar.png');
    });

    it('should set alt attribute on img when alt input is provided', () => {
      fixture.componentRef.setInput('src', 'https://example.com/avatar.png');
      fixture.componentRef.setInput('alt', 'Jane Doe');
      fixture.detectChanges();

      const img = fixture.nativeElement.querySelector(
        'img',
      ) as HTMLImageElement;
      expect(img.alt).toBe('Jane Doe');
    });

    it('should not render img element when src is null', () => {
      fixture.componentRef.setInput('src', null);
      fixture.componentRef.setInput('initials', 'JD');
      fixture.detectChanges();

      const img = fixture.nativeElement.querySelector('img');
      expect(img).toBeNull();
    });
  });

  describe('initials fallback', () => {
    it('should display initials when src is null', () => {
      fixture.componentRef.setInput('src', null);
      fixture.componentRef.setInput('initials', 'AB');
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent?.trim()).toBe('AB');
    });

    it('should hide initials span with aria-hidden when src is absent', () => {
      fixture.componentRef.setInput('src', null);
      fixture.componentRef.setInput('initials', 'XY');
      fixture.detectChanges();

      const initialsSpan = fixture.nativeElement.querySelector(
        '[aria-hidden="true"]',
      ) as HTMLElement;
      expect(initialsSpan).toBeTruthy();
      expect(initialsSpan.textContent?.trim()).toBe('XY');
    });

    it('should show empty initials when initials input defaults to empty string', () => {
      fixture.componentRef.setInput('src', null);
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      // textContent will be empty string — no crash
      expect(el.textContent?.trim()).toBe('');
    });
  });

  describe('size classes', () => {
    it('should apply size-6 class when size is sm', () => {
      fixture.componentRef.setInput('size', 'sm');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('size-6');
    });

    it('should apply size-8 class when size is md', () => {
      fixture.componentRef.setInput('size', 'md');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('size-8');
    });

    it('should apply size-11 class when size is lg', () => {
      fixture.componentRef.setInput('size', 'lg');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('size-11');
    });

    it('should default to md size when size input is not provided', () => {
      fixture.detectChanges();

      expect(component.size()).toBe('md');
      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.className).toContain('size-8');
    });
  });

  describe('actor colours', () => {
    it('should apply inline background-color style when actor is human', () => {
      fixture.componentRef.setInput('actor', 'human');
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      expect(span.style.backgroundColor).toBeTruthy();
    });

    it('should not apply inline colour styles when actor is null', () => {
      fixture.componentRef.setInput('actor', null);
      fixture.detectChanges();

      const span = fixture.nativeElement.querySelector('span') as HTMLElement;
      // style.backgroundColor is empty string when not set
      expect(span.style.backgroundColor).toBe('');
    });

    it('should apply different background colours for claude-code vs human', () => {
      // Render human actor
      fixture.componentRef.setInput('actor', 'human');
      fixture.detectChanges();
      const humanBg = (
        fixture.nativeElement.querySelector('span') as HTMLElement
      ).style.backgroundColor;

      // Render claude-code actor
      fixture.componentRef.setInput('actor', 'claude-code');
      fixture.detectChanges();
      const codeBg = (
        fixture.nativeElement.querySelector('span') as HTMLElement
      ).style.backgroundColor;

      expect(humanBg).not.toBe(codeBg);
    });
  });

  describe('testId', () => {
    it('should set data-testid attribute when testId input is provided', () => {
      fixture.componentRef.setInput('testId', 'user-avatar');
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector(
        '[data-testid="user-avatar"]',
      );
      expect(el).toBeTruthy();
    });

    it('should not render data-testid attribute when testId is null', () => {
      fixture.componentRef.setInput('testId', null);
      fixture.detectChanges();

      const el = fixture.nativeElement.querySelector('[data-testid]');
      expect(el).toBeNull();
    });
  });
});
