import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
  signal,
  input,
  viewChild,
  ElementRef,
} from '@angular/core';
import {
  FormBuilder,
  FormControl,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  ArrowLeft,
  Save,
  Send,
  Info,
  Type,
  FileText,
  Globe,
  Image,
  Tag,
  X,
  Edit,
  Eye,
  Columns2,
  Bold,
  Italic,
  Link,
  Code,
  Upload,
  Loader2,
  Trash2,
  Sparkles,
  Check,
  RotateCcw,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { UploadService } from '../../core/services/upload.service';
import { FlowPolishService } from '../../core/services/flow-polish.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ContentType,
  ContentStatus,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
} from '../../core/models';
import { TextFieldModule } from '@angular/cdk/text-field';
import type { HasUnsavedChanges } from '../../core/guards/unsaved-changes.guard';

const STATUS_OPTIONS: { value: ContentStatus; label: string }[] = [
  { value: 'draft', label: 'Draft' },
  { value: 'published', label: 'Published' },
  { value: 'archived', label: 'Archived' },
];

const EDITOR_TYPE_OPTIONS: { value: ContentType; label: string }[] = [
  { value: 'article', label: 'Article' },
  { value: 'essay', label: 'Essay' },
];

@Component({
  selector: 'app-article-editor',
  standalone: true,
  imports: [ReactiveFormsModule, LucideAngularModule, TextFieldModule],
  templateUrl: './article-editor.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleEditorComponent implements OnInit, HasUnsavedChanges {
  /** Route param: admin/editor/:id (undefined for new articles) */
  readonly id = input<string>();

  private readonly fb = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly articleService = inject(ArticleService);
  private readonly markdownService = inject(MarkdownService);
  private readonly uploadService = inject(UploadService);
  private readonly flowPolishService = inject(FlowPolishService);
  private readonly notificationService = inject(NotificationService);

  protected readonly isLoading = signal(false);
  protected readonly isSaving = signal(false);
  protected readonly isNewArticle = signal(true);
  protected readonly contentType = signal<ContentType>('article');
  protected readonly previewHtml = signal('');
  protected readonly selectedTab = signal<'edit' | 'preview' | 'split'>('edit');
  protected readonly isUploading = signal(false);
  private readonly isFormDirty = signal(false);

  // ─── AI Polish ───
  protected readonly isPolishing = signal(false);
  protected readonly polishState = signal<
    'idle' | 'triggered' | 'ready' | 'error'
  >('idle');
  protected readonly polishedBody = signal<string | null>(null);
  protected readonly originalBody = signal<string | null>(null);

  /** Article ID stored in edit mode */
  private articleId: string | null = null;

  protected readonly articleForm: FormGroup;

  protected readonly statusOptions = STATUS_OPTIONS;
  protected readonly editorTypeOptions = EDITOR_TYPE_OPTIONS;

  protected readonly availableTags = [
    'Angular',
    'TypeScript',
    'JavaScript',
    'Golang',
    'Rust',
    'Flutter',
    'Web Dev',
    'Frontend',
    'Backend',
  ];

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly SaveIcon = Save;
  protected readonly SendIcon = Send;
  protected readonly InfoIcon = Info;
  protected readonly TypeIcon = Type;
  protected readonly FileTextIcon = FileText;
  protected readonly GlobeIcon = Globe;
  protected readonly ImageIcon = Image;
  protected readonly TagIcon = Tag;
  protected readonly XIcon = X;
  protected readonly EditIcon = Edit;
  protected readonly EyeIcon = Eye;
  protected readonly Columns2Icon = Columns2;
  protected readonly BoldIcon = Bold;
  protected readonly ItalicIcon = Italic;
  protected readonly LinkIcon = Link;
  protected readonly CodeIcon = Code;
  protected readonly UploadIcon = Upload;
  protected readonly Loader2Icon = Loader2;
  protected readonly Trash2Icon = Trash2;
  protected readonly SparklesIcon = Sparkles;
  protected readonly CheckIcon = Check;
  protected readonly RotateCcwIcon = RotateCcw;

  private readonly bodyTextarea =
    viewChild.required<ElementRef<HTMLTextAreaElement>>('bodyTextarea');

  protected get bodyControl(): FormControl<string> {
    return this.articleForm.get('body') as FormControl<string>;
  }

  constructor() {
    this.articleForm = this.fb.group({
      title: ['', [Validators.required, Validators.minLength(5)]],
      slug: ['', [Validators.required]],
      excerpt: ['', [Validators.required, Validators.maxLength(200)]],
      body: ['', [Validators.required, Validators.minLength(50)]],
      tags: [[] as string[]],
      status: ['draft' as ContentStatus, Validators.required],
      cover_image: [''],
    });

    this.articleForm
      .get('body')
      ?.valueChanges.pipe(takeUntilDestroyed())
      .subscribe((body: string) => {
        if (body) {
          this.updatePreview(body);
        }
      });

    this.articleForm.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => {
      this.isFormDirty.set(true);
    });
  }

  hasUnsavedChanges(): boolean {
    return this.isFormDirty() && !this.isSaving();
  }

  ngOnInit(): void {
    const idValue = this.id();
    if (idValue) {
      this.isNewArticle.set(false);
      this.loadArticle(idValue);
    } else {
      const defaultContent = this.getDefaultMarkdown();
      this.articleForm.patchValue({ body: defaultContent });
      this.updatePreview(defaultContent);
    }
  }

  private loadArticle(id: string): void {
    this.isLoading.set(true);

    this.articleService.getArticleBySlug(id).subscribe({
      next: (article) => {
        this.articleId = article.id;
        if (article.type === 'article' || article.type === 'essay') {
          this.contentType.set(article.type);
        }
        this.articleForm.patchValue({
          title: article.title,
          slug: article.slug,
          excerpt: article.excerpt,
          body: article.body,
          tags: article.tags,
          status: article.status,
          cover_image: article.cover_image ?? '',
        });
        this.updatePreview(article.body);
        this.isLoading.set(false);
      },
      error: () => {
        this.notificationService.error('Failed to load article');
        this.isLoading.set(false);
      },
    });
  }

  private updatePreview(markdown: string): void {
    this.previewHtml.set(this.markdownService.parse(markdown));
    this.markdownService.initializeMermaid();
  }

  private getDefaultMarkdown(): string {
    return `# New Article Title

> This is a blockquote example

## Introduction

Start writing your article here...

## Code Example

\`\`\`typescript
interface User {
  id: string;
  name: string;
  email: string;
}
\`\`\`

## Conclusion

Summarize your thoughts here...
`;
  }

  protected onTabChange(tab: 'edit' | 'preview' | 'split'): void {
    this.selectedTab.set(tab);
    setTimeout(() => {
      const body = this.articleForm.get('body')?.value || '';
      this.updatePreview(body);
    }, 100);
  }

  protected onContentChange(event: Event): void {
    const textarea = event.target as HTMLTextAreaElement;
    const body = textarea.value;
    this.articleForm.patchValue({ body }, { emitEvent: false });
    this.updatePreview(body);
  }

  protected addTag(tag: string): void {
    const currentTags: string[] = this.articleForm.get('tags')?.value || [];
    if (!currentTags.includes(tag)) {
      this.articleForm.patchValue({ tags: [...currentTags, tag] });
    }
  }

  protected removeTag(tagToRemove: string): void {
    const currentTags: string[] = this.articleForm.get('tags')?.value || [];
    this.articleForm.patchValue({
      tags: currentTags.filter((tag) => tag !== tagToRemove),
    });
  }

  protected get selectedTags(): string[] {
    return this.articleForm.get('tags')?.value || [];
  }

  protected saveDraft(): void {
    this.saveArticle('draft');
  }

  protected publish(): void {
    this.saveArticle('published');
  }

  private saveArticle(status: ContentStatus): void {
    if (this.articleForm.invalid) {
      this.markFormGroupTouched();
      this.notificationService.error('Please fill in all required fields');
      return;
    }

    this.isSaving.set(true);

    const formValue = this.articleForm.value;
    const excerpt = formValue.excerpt || this.generateExcerpt(formValue.body);

    if (this.isNewArticle()) {
      const request: ApiCreateContentRequest = {
        title: formValue.title,
        slug: formValue.slug,
        body: formValue.body,
        excerpt,
        type: this.contentType(),
        status,
        tags: formValue.tags,
        cover_image: formValue.cover_image || undefined,
      };

      this.articleService.createArticle(request).subscribe({
        next: () => {
          this.notificationService.success(
            status === 'published' ? 'Article published!' : 'Draft saved!',
          );
          this.isFormDirty.set(false);
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.notificationService.error('Failed to save');
          this.isSaving.set(false);
        },
      });
    } else {
      const articleId = this.articleId;
      if (!articleId) {
        this.notificationService.error('Article ID is missing');
        this.isSaving.set(false);
        return;
      }

      const request: ApiUpdateContentRequest = {
        title: formValue.title,
        slug: formValue.slug,
        body: formValue.body,
        excerpt,
        status,
        tags: formValue.tags,
        cover_image: formValue.cover_image || undefined,
      };

      this.articleService.updateArticle(articleId, request).subscribe({
        next: () => {
          this.notificationService.success(
            status === 'published' ? 'Article published!' : 'Draft saved!',
          );
          this.isFormDirty.set(false);
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.notificationService.error('Failed to update');
          this.isSaving.set(false);
        },
      });
    }
  }

  private generateExcerpt(body: string): string {
    const textContent = body.replace(/[#*`]/g, '').replace(/\n/g, ' ').trim();
    return textContent.length > 150
      ? textContent.substring(0, 150) + '...'
      : textContent;
  }

  private markFormGroupTouched(): void {
    Object.keys(this.articleForm.controls).forEach((key) => {
      const control = this.articleForm.get(key);
      control?.markAsTouched();
    });
  }

  protected getFieldError(fieldName: string): string {
    const control = this.articleForm.get(fieldName);
    if (control?.errors && control.touched) {
      if (control.errors['required']) {
        return 'This field is required';
      }
      if (control.errors['minlength']) {
        const minLength = control.errors['minlength'].requiredLength;
        return `Must be at least ${minLength} characters`;
      }
      if (control.errors['maxlength']) {
        const maxLength = control.errors['maxlength'].requiredLength;
        return `Must be at most ${maxLength} characters`;
      }
    }
    return '';
  }

  protected onCoverImageSelect(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      return;
    }

    const validationError = this.uploadService.validate(file);
    if (validationError) {
      this.notificationService.error(validationError);
      input.value = '';
      return;
    }

    this.isUploading.set(true);
    this.uploadService.upload(file).subscribe({
      next: (result) => {
        this.articleForm.patchValue({ cover_image: result.url });
        this.isUploading.set(false);
        this.notificationService.success('Cover image uploaded successfully');
        input.value = '';
      },
      error: () => {
        this.isUploading.set(false);
        this.notificationService.error('Image upload failed');
        input.value = '';
      },
    });
  }

  protected removeCoverImage(): void {
    this.articleForm.patchValue({ cover_image: '' });
  }

  protected insertFormatting(
    prefix: string,
    suffix: string,
    placeholder: string,
  ): void {
    const textarea = this.bodyTextarea().nativeElement;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;
    const selected = text.substring(start, end);

    const insertion = selected || placeholder;
    const newText =
      text.substring(0, start) +
      prefix +
      insertion +
      suffix +
      text.substring(end);

    this.articleForm.patchValue({ body: newText });
    this.updatePreview(newText);

    setTimeout(() => {
      textarea.focus();
      const cursorPos = selected
        ? start + prefix.length + selected.length + suffix.length
        : start + prefix.length;
      const selEnd = selected ? cursorPos : cursorPos + placeholder.length;
      textarea.setSelectionRange(cursorPos, selected ? cursorPos : selEnd);
    }, 0);
  }

  protected insertBold(): void {
    this.insertFormatting('**', '**', 'bold text');
  }

  protected insertItalic(): void {
    this.insertFormatting('*', '*', 'italic text');
  }

  protected insertLink(): void {
    this.insertFormatting('[', '](url)', 'link text');
  }

  protected insertCode(): void {
    this.insertFormatting('`', '`', 'code');
  }

  protected insertImage(): void {
    this.insertFormatting('![', '](url)', 'alt text');
  }

  // ─── AI Polish ───

  protected triggerPolish(): void {
    const contentId = this.articleId;
    if (!contentId || this.isNewArticle()) {
      this.notificationService.error(
        'Please save the article before using AI polish',
      );
      return;
    }

    this.isPolishing.set(true);
    this.polishState.set('triggered');

    this.flowPolishService.triggerPolish(contentId).subscribe({
      next: () => {
        this.notificationService.success('AI polish triggered, processing...');
        this.pollPolishResult(contentId);
      },
      error: () => {
        this.isPolishing.set(false);
        this.polishState.set('error');
        this.notificationService.error('Failed to trigger AI polish');
      },
    });
  }

  private pollPolishResult(contentId: string): void {
    const maxAttempts = 30;
    let attempt = 0;
    const poll = (): void => {
      attempt++;
      this.flowPolishService.getResult(contentId).subscribe({
        next: (result) => {
          this.originalBody.set(result.original_body);
          this.polishedBody.set(result.polished_body);
          this.polishState.set('ready');
          this.isPolishing.set(false);
          this.notificationService.success(
            'AI polish complete, please review the result',
          );
        },
        error: () => {
          if (attempt < maxAttempts) {
            setTimeout(poll, 3000);
          } else {
            this.isPolishing.set(false);
            this.polishState.set('error');
            this.notificationService.error(
              'AI polish timed out, please try again later',
            );
          }
        },
      });
    };
    setTimeout(poll, 3000);
  }

  protected applyPolish(): void {
    const polished = this.polishedBody();
    if (!polished) {
      return;
    }

    this.articleForm.patchValue({ body: polished });
    this.updatePreview(polished);
    this.polishState.set('idle');
    this.polishedBody.set(null);
    this.originalBody.set(null);
    this.notificationService.success('Polish result applied');
  }

  protected approvePolish(): void {
    const contentId = this.articleId;
    if (!contentId) {
      return;
    }

    this.flowPolishService.approve(contentId).subscribe({
      next: () => {
        this.applyPolish();
        this.notificationService.success('Polish approved and saved');
      },
      error: () => this.notificationService.error('Approval failed'),
    });
  }

  protected discardPolish(): void {
    this.polishState.set('idle');
    this.polishedBody.set(null);
    this.originalBody.set(null);
  }

  protected cancel(): void {
    this.router.navigate(['/admin']);
  }
}
