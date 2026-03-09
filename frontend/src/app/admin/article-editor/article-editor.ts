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
import { ArticleStatus } from '../../core/models';

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

  protected readonly articleForm: FormGroup;

  protected readonly statusOptions = [
    { value: ArticleStatus.DRAFT, label: '草稿' },
    { value: ArticleStatus.PUBLISHED, label: '已發布' },
    { value: ArticleStatus.ARCHIVED, label: '封存' },
  ];

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
      excerpt: ['', [Validators.required, Validators.maxLength(200)]],
      content: ['', [Validators.required, Validators.minLength(50)]],
      tags: [[] as string[]],
      status: [ArticleStatus.DRAFT, Validators.required],
      coverImage: [''],
    });

    this.articleForm
      .get('content')
      ?.valueChanges.pipe(takeUntilDestroyed())
      .subscribe((content) => {
        if (content) {
          this.updatePreview(content);
        }
      });
  }

  ngOnInit(): void {
    const articleId = this.route.snapshot.paramMap.get('id');
    if (articleId) {
      this.isNewArticle.set(false);
      this.loadArticle(articleId);
    } else {
      const defaultContent = this.getDefaultMarkdown();
      this.articleForm.patchValue({ content: defaultContent });
      this.updatePreview(defaultContent);
    }
  }

  private loadArticle(id: string): void {
    this.isLoading.set(true);

    const article = this.articleService.articleList().find((a) => a.id === id);

    if (article) {
      this.articleForm.patchValue({
        title: article.title,
        excerpt: article.excerpt,
        content: article.content,
        tags: article.tags,
        status: article.status,
        coverImage: article.coverImage,
      });
      this.updatePreview(article.content);
    }

    this.isLoading.set(false);
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
      const content = this.articleForm.get('content')?.value || '';
      this.updatePreview(content);
    }, 100);
  }

  protected onContentChange(event: Event): void {
    const textarea = event.target as HTMLTextAreaElement;
    const content = textarea.value;
    this.articleForm.patchValue({ content }, { emitEvent: false });
    this.updatePreview(content);
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
    this.saveArticle(ArticleStatus.DRAFT);
  }

  protected publish(): void {
    this.saveArticle(ArticleStatus.PUBLISHED);
  }

  private saveArticle(status: ArticleStatus): void {
    if (this.articleForm.invalid) {
      this.markFormGroupTouched();
      this.showNotification('請填寫所有必要欄位', 'error');
      return;
    }

    this.isSaving.set(true);

    const formValue = this.articleForm.value;
    const articleData = {
      ...formValue,
      status,
      excerpt: formValue.excerpt || this.generateExcerpt(formValue.content),
    };

    setTimeout(() => {
      this.showNotification(
        status === ArticleStatus.PUBLISHED ? '文章已發布！' : '草稿已保存！',
        'success',
      );
      this.isSaving.set(false);
      this.router.navigate(['/admin']);
    }, 1500);
  }

  private showNotification(message: string, type: 'success' | 'error'): void {
    this.notification.set({ message, type });
    setTimeout(() => this.notification.set(null), 3000);
  }

  private generateExcerpt(content: string): string {
    const textContent = content
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
