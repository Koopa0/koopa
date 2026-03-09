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
import { LucideAngularModule, ArrowLeft, Save, Plus, X } from 'lucide-angular';
import { ProjectService } from '../../core/services/project/project.service';
import { ProjectStatus } from '../../core/models';

@Component({
  selector: 'app-project-editor',
  standalone: true,
  imports: [ReactiveFormsModule, LucideAngularModule],
  templateUrl: './project-editor.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProjectEditorComponent implements OnInit {
  private readonly fb = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly projectService = inject(ProjectService);

  protected readonly isLoading = signal(false);
  protected readonly isSaving = signal(false);
  protected readonly isNewProject = signal(true);
  protected readonly notification = signal<{
    message: string;
    type: 'success' | 'error';
  } | null>(null);

  protected readonly projectForm: FormGroup;

  protected readonly statusOptions: Array<{
    value: ProjectStatus;
    label: string;
  }> = [
    { value: 'in-progress', label: 'In Progress' },
    { value: 'completed', label: 'Completed' },
    { value: 'maintained', label: 'Maintained' },
  ];

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly SaveIcon = Save;
  protected readonly PlusIcon = Plus;
  protected readonly XIcon = X;

  // 暫存 tech stack 和 highlights 的新增欄位
  protected readonly newTech = signal('');
  protected readonly newHighlight = signal('');

  constructor() {
    this.projectForm = this.fb.group({
      title: ['', [Validators.required, Validators.minLength(2)]],
      slug: ['', [Validators.required]],
      description: ['', [Validators.required, Validators.maxLength(300)]],
      longDescription: [''],
      techStack: [[] as string[]],
      role: ['', [Validators.required]],
      highlights: [[] as string[]],
      githubUrl: [''],
      liveUrl: [''],
      featured: [false],
      order: [0],
      status: ['in-progress' as ProjectStatus, Validators.required],
    });
  }

  ngOnInit(): void {
    const projectId = this.route.snapshot.paramMap.get('id');
    if (projectId) {
      this.isNewProject.set(false);
      this.loadProject(projectId);
    }
  }

  private loadProject(id: string): void {
    this.isLoading.set(true);
    const project = this.projectService.getProjectById(id);

    if (project) {
      this.projectForm.patchValue({
        title: project.title,
        slug: project.slug,
        description: project.description,
        longDescription: project.longDescription || '',
        techStack: project.techStack,
        role: project.role,
        highlights: project.highlights,
        githubUrl: project.githubUrl || '',
        liveUrl: project.liveUrl || '',
        featured: project.featured,
        order: project.order,
        status: project.status,
      });
    }

    this.isLoading.set(false);
  }

  protected addTech(): void {
    const tech = this.newTech().trim();
    if (!tech) {
      return;
    }

    const current: string[] = this.projectForm.get('techStack')?.value || [];
    if (!current.includes(tech)) {
      this.projectForm.patchValue({ techStack: [...current, tech] });
    }
    this.newTech.set('');
  }

  protected removeTech(techToRemove: string): void {
    const current: string[] = this.projectForm.get('techStack')?.value || [];
    this.projectForm.patchValue({
      techStack: current.filter((t) => t !== techToRemove),
    });
  }

  protected addHighlight(): void {
    const highlight = this.newHighlight().trim();
    if (!highlight) {
      return;
    }

    const current: string[] = this.projectForm.get('highlights')?.value || [];
    this.projectForm.patchValue({ highlights: [...current, highlight] });
    this.newHighlight.set('');
  }

  protected removeHighlight(index: number): void {
    const current: string[] = this.projectForm.get('highlights')?.value || [];
    this.projectForm.patchValue({
      highlights: current.filter((_, i) => i !== index),
    });
  }

  protected get techStack(): string[] {
    return this.projectForm.get('techStack')?.value || [];
  }

  protected get highlights(): string[] {
    return this.projectForm.get('highlights')?.value || [];
  }

  protected onTechInput(event: Event): void {
    this.newTech.set((event.target as HTMLInputElement).value);
  }

  protected onTechKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.addTech();
    }
  }

  protected onHighlightInput(event: Event): void {
    this.newHighlight.set((event.target as HTMLInputElement).value);
  }

  protected onHighlightKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.addHighlight();
    }
  }

  protected save(): void {
    if (this.projectForm.invalid) {
      this.markFormGroupTouched();
      this.showNotification('請填寫所有必要欄位', 'error');
      return;
    }

    this.isSaving.set(true);
    const formValue = this.projectForm.value;

    if (this.isNewProject()) {
      this.projectService.createProject(formValue).subscribe({
        next: () => {
          this.showNotification('專案已建立！', 'success');
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.showNotification('建立失敗', 'error');
          this.isSaving.set(false);
        },
      });
    } else {
      const id = this.route.snapshot.paramMap.get('id')!;
      this.projectService.updateProject({ ...formValue, id }).subscribe({
        next: () => {
          this.showNotification('專案已更新！', 'success');
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

  protected cancel(): void {
    this.router.navigate(['/admin']);
  }

  protected getFieldError(fieldName: string): string {
    const control = this.projectForm.get(fieldName);
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

  private showNotification(message: string, type: 'success' | 'error'): void {
    this.notification.set({ message, type });
    setTimeout(() => this.notification.set(null), 3000);
  }

  private markFormGroupTouched(): void {
    Object.keys(this.projectForm.controls).forEach((key) => {
      const control = this.projectForm.get(key);
      control?.markAsTouched();
    });
  }
}
