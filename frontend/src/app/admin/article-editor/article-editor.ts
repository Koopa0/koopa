import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
  signal,
  input,
} from '@angular/core';
import {
  FormBuilder,
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
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { MarkdownService } from '../../core/services/markdown.service';
import { UploadService } from '../../core/services/upload.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ContentStatus,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
} from '../../core/models';

const STATUS_OPTIONS: { value: ContentStatus; label: string }[] = [
  { value: 'draft', label: 'Draft' },
  { value: 'published', label: 'Published' },
  { value: 'archived', label: 'Archived' },
];

@Component({
  selector: 'app-article-editor',
  standalone: true,
  imports: [ReactiveFormsModule, LucideAngularModule],
  templateUrl: './article-editor.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleEditorComponent implements OnInit {
  /** Route param: admin/editor/:id (undefined for new articles) */
  readonly id = input<string>();

  private readonly fb = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly articleService = inject(ArticleService);
  private readonly markdownService = inject(MarkdownService);
  private readonly uploadService = inject(UploadService);
  private readonly notificationService = inject(NotificationService);

  protected readonly isLoading = signal(false);
  protected readonly isSaving = signal(false);
  protected readonly isNewArticle = signal(true);
  protected readonly previewHtml = signal('');
  protected readonly selectedTab = signal<'edit' | 'preview' | 'split'>('edit');
  protected readonly isUploading = signal(false);

  /** Article ID stored in edit mode */
  private articleId: string | null = null;

  protected readonly articleForm: FormGroup;

  protected readonly statusOptions = STATUS_OPTIONS;

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
    const excerpt =
      formValue.excerpt || this.generateExcerpt(formValue.body);

    if (this.isNewArticle()) {
      const request: ApiCreateContentRequest = {
        title: formValue.title,
        slug: formValue.slug,
        body: formValue.body,
        excerpt,
        type: 'article',
        status,
        tags: formValue.tags,
        cover_image: formValue.cover_image || undefined,
      };

      this.articleService.createArticle(request).subscribe({
        next: () => {
          this.notificationService.success(
            status === 'published' ? 'Article published!' : 'Draft saved!',
          );
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
    const textContent = body
      .replace(/[#*`]/g, '')
      .replace(/\n/g, ' ')
      .trim();
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
        this.notificationService.success('封面圖片上傳成功');
        input.value = '';
      },
      error: () => {
        this.isUploading.set(false);
        this.notificationService.error('圖片上傳失敗');
        input.value = '';
      },
    });
  }

  protected removeCoverImage(): void {
    this.articleForm.patchValue({ cover_image: '' });
  }

  protected cancel(): void {
    this.router.navigate(['/admin']);
  }
}
