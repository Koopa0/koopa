import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ContentTypeComponent, ContentType } from './content-type.component';

describe('ContentTypeComponent', () => {
  let fixture: ComponentFixture<ContentTypeComponent>;
  let component: ContentTypeComponent;

  // Helper: re-create fixture with a fresh type input each time
  async function setup(type: ContentType): Promise<void> {
    await TestBed.configureTestingModule({
      imports: [ContentTypeComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(ContentTypeComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('type', type);
    fixture.detectChanges();
  }

  it('should create when type is "article"', async () => {
    await setup('article');
    expect(component).toBeTruthy();
  });

  describe('data-testid', () => {
    it('should set data-testid to "content-type-article" when type is article', async () => {
      await setup('article');
      const el = fixture.nativeElement.querySelector(
        '[data-testid="content-type-article"]',
      );
      expect(el).toBeTruthy();
    });

    it('should set data-testid to "content-type-til" when type is til', async () => {
      await setup('til');
      const el = fixture.nativeElement.querySelector(
        '[data-testid="content-type-til"]',
      );
      expect(el).toBeTruthy();
    });

    it('should set data-testid to "content-type-build-log" when type is build-log', async () => {
      await setup('build-log');
      const el = fixture.nativeElement.querySelector(
        '[data-testid="content-type-build-log"]',
      );
      expect(el).toBeTruthy();
    });
  });

  describe('label text', () => {
    const types: ContentType[] = [
      'article',
      'essay',
      'build-log',
      'til',
      'note',
      'digest',
    ];

    for (const type of types) {
      it(`should render lowercase type name "${type}" when type is ${type}`, async () => {
        await setup(type);
        const el = fixture.nativeElement.querySelector(
          `[data-testid="content-type-${type}"]`,
        );
        expect(el.textContent).toContain(type);
      });
    }
  });

  describe('dot color', () => {
    it('should apply CSS variable for dot color matching the type', async () => {
      await setup('essay');
      const dot = fixture.nativeElement.querySelector(
        '[data-testid="content-type-essay"] span[aria-hidden="true"]',
      ) as HTMLElement;
      expect(dot.style.backgroundColor).toBe('var(--dot-essay)');
    });

    it('should apply different CSS variable when type changes', async () => {
      await setup('digest');
      const dot = fixture.nativeElement.querySelector(
        '[data-testid="content-type-digest"] span[aria-hidden="true"]',
      ) as HTMLElement;
      expect(dot.style.backgroundColor).toBe('var(--dot-digest)');
    });

    it('should mark dot span as aria-hidden', async () => {
      await setup('note');
      const dot = fixture.nativeElement.querySelector(
        '[data-testid="content-type-note"] span[aria-hidden="true"]',
      );
      expect(dot).toBeTruthy();
      expect(dot.getAttribute('aria-hidden')).toBe('true');
    });
  });

  describe('type input update', () => {
    it('should re-render with new type name when type input changes', async () => {
      await setup('article');
      fixture.componentRef.setInput('type', 'til');
      fixture.detectChanges();
      await fixture.whenStable();

      const newEl = fixture.nativeElement.querySelector(
        '[data-testid="content-type-til"]',
      );
      expect(newEl).toBeTruthy();
      expect(newEl.textContent).toContain('til');

      // old testid should be gone
      const oldEl = fixture.nativeElement.querySelector(
        '[data-testid="content-type-article"]',
      );
      expect(oldEl).toBeNull();
    });
  });
});
