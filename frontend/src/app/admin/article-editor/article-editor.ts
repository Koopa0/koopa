import {
  Component,
  inject,
  ChangeDetectionStrategy,
  OnInit,
  signal,
} from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
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
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { MarkdownService } from '../../core/services/markdown.service';
import type {
  ContentStatus,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
} from '../../core/models';

const STATUS_OPTIONS: Array<{ value: ContentStatus; label: string }> = [
  { value: 'draft', label: '草稿' },
  { value: 'published', label: '已發布' },
  { value: 'archived', label: '封存' },
];

@Component({
  selector: 'app-article-editor',
  standalone: true,
  imports: [ReactiveFormsModule, LucideAngularModule],
  templateUrl: './article-editor.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ArticleEditorComponent implements OnInit {
  private readonly fb = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly articleService = inject(ArticleService);
  private readonly markdownService = inject(MarkdownService);

  protected readonly isLoading = signal(false);
  protected readonly isSaving = signal(false);
  protected readonly isNewArticle = signal(true);
  protected readonly previewHtml = signal('');
  protected readonly selectedTab = signal<'edit' | 'preview' | 'split'>('edit');
  protected readonly notification = signal<{
    message: string;
    type: 'success' | 'error';
  } | null>(null);

  /** 編輯模式下儲存文章 ID */
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
    'Web開發',
    '前端',
    '後端',
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
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.isNewArticle.set(false);
      this.loadArticle(slug);
    } else {
      const defaultContent = this.getDefaultMarkdown();
      this.articleForm.patchValue({ body: defaultContent });
      this.updatePreview(defaultContent);
    }
  }

  private loadArticle(slug: string): void {
    this.isLoading.set(true);

    this.articleService.getArticleBySlug(slug).subscribe({
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
        this.showNotification('載入文章失敗', 'error');
        this.isLoading.set(false);
      },
    });
  }

  private updatePreview(markdown: string): void {
    this.previewHtml.set(this.markdownService.parse(markdown));
    this.markdownService.initializeMermaid();
  }

  private getDefaultMarkdown(): string {
    return `# 新文章標題

> 這裡是一個引用範例

## 介紹

在這裡開始撰寫您的技術文章...

## 程式碼範例

\`\`\`typescript
interface User {
  id: string;
  name: string;
  email: string;
}
\`\`\`

## 結論

在這裡總結您的想法...
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
      this.showNotification('請填寫所有必要欄位', 'error');
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
          this.showNotification(
            status === 'published' ? '文章已發布！' : '草稿已保存！',
            'success',
          );
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.showNotification('儲存失敗', 'error');
          this.isSaving.set(false);
        },
      });
    } else {
      const request: ApiUpdateContentRequest = {
        title: formValue.title,
        slug: formValue.slug,
        body: formValue.body,
        excerpt,
        status,
        tags: formValue.tags,
        cover_image: formValue.cover_image || undefined,
      };

      this.articleService.updateArticle(this.articleId!, request).subscribe({
        next: () => {
          this.showNotification(
            status === 'published' ? '文章已發布！' : '草稿已保存！',
            'success',
          );
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.showNotification('更新失敗', 'error');
          this.isSaving.set(false);
        },
      });
    }
  }

  private showNotification(message: string, type: 'success' | 'error'): void {
    this.notification.set({ message, type });
    setTimeout(() => this.notification.set(null), 3000);
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
        return '此欄位為必填';
      }
      if (control.errors['minlength']) {
        const minLength = control.errors['minlength'].requiredLength;
        return `至少需要 ${minLength} 個字符`;
      }
      if (control.errors['maxlength']) {
        const maxLength = control.errors['maxlength'].requiredLength;
        return `最多 ${maxLength} 個字符`;
      }
    }
    return '';
  }

  protected cancel(): void {
    this.router.navigate(['/admin']);
  }
}
