import {
  Directive,
  ElementRef,
  Renderer2,
  OnInit,
  inject,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

@Directive({
  selector: 'pre[appCopyButton]',
  standalone: true,
})
export class CopyButtonDirective implements OnInit {
  private readonly el = inject(ElementRef);
  private readonly renderer = inject(Renderer2);
  private readonly platformId = inject(PLATFORM_ID);

  ngOnInit(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    const button = this.renderer.createElement('button');
    this.renderer.setAttribute(button, 'type', 'button');
    this.renderer.setAttribute(button, 'title', 'Copy code');
    this.renderer.setAttribute(
      button,
      'class',
      'absolute right-2 top-2 rounded-sm bg-zinc-700 px-2 py-1 text-xs text-zinc-300 opacity-0 transition-opacity hover:bg-zinc-600 group-hover:opacity-100',
    );

    const text = this.renderer.createText('Copy');
    this.renderer.appendChild(button, text);

    const pre = this.el.nativeElement;
    this.renderer.setStyle(pre, 'position', 'relative');
    this.renderer.addClass(pre, 'group');
    this.renderer.appendChild(pre, button);

    this.renderer.listen(button, 'click', () => this.copyCode(button));
  }

  private copyCode(button: HTMLButtonElement): void {
    const code = this.el.nativeElement.querySelector('code');
    if (!code) {
      return;
    }

    const text = code.textContent || '';

    navigator.clipboard
      .writeText(text)
      .then(() => {
        button.textContent = 'Copied!';
        setTimeout(() => {
          button.textContent = 'Copy';
        }, 2000);
      })
      .catch(() => {
        button.textContent = 'Copy failed';
        setTimeout(() => {
          button.textContent = 'Copy';
        }, 2000);
      });
  }
}
