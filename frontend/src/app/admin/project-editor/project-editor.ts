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
import type {
  ProjectStatus,
  ApiCreateProjectRequest,
  ApiUpdateProjectRequest,
} from '../../core/models';

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

  /** Project ID stored in edit mode */
  private projectId: string | null = null;

  protected readonly projectForm: FormGroup;

  protected readonly statusOptions: Array<{
    value: ProjectStatus;
    label: string;
  }> = [
    { value: 'in-progress', label: 'In Progress' },
    { value: 'completed', label: 'Completed' },
    { value: 'maintained', label: 'Maintained' },
    { value: 'archived', label: 'Archived' },
  ];

  protected readonly ArrowLeftIcon = ArrowLeft;
  protected readonly SaveIcon = Save;
  protected readonly PlusIcon = Plus;
  protected readonly XIcon = X;

  // Temporary input fields for adding tech stack and highlights
  protected readonly newTech = signal('');
  protected readonly newHighlight = signal('');

  constructor() {
    this.projectForm = this.fb.group({
      title: ['', [Validators.required, Validators.minLength(2)]],
      slug: ['', [Validators.required]],
      description: ['', [Validators.required, Validators.maxLength(300)]],
      long_description: [''],
      tech_stack: [[] as string[]],
      role: ['', [Validators.required]],
      highlights: [[] as string[]],
      github_url: [''],
      live_url: [''],
      featured: [false],
      sort_order: [0],
      status: ['in-progress' as ProjectStatus, Validators.required],
    });
  }

  ngOnInit(): void {
    const slug = this.route.snapshot.paramMap.get('slug');
    if (slug) {
      this.isNewProject.set(false);
      this.loadProject(slug);
    }
  }

  private loadProject(slug: string): void {
    this.isLoading.set(true);

    this.projectService.getProjectBySlug(slug).subscribe({
      next: (project) => {
        this.projectId = project.id;
        this.projectForm.patchValue({
          title: project.title,
          slug: project.slug,
          description: project.description,
          long_description: project.long_description ?? '',
          tech_stack: project.tech_stack,
          role: project.role,
          highlights: project.highlights,
          github_url: project.github_url ?? '',
          live_url: project.live_url ?? '',
          featured: project.featured,
          sort_order: project.sort_order,
          status: project.status,
        });
        this.isLoading.set(false);
      },
      error: () => {
        this.showNotification('Failed to load project', 'error');
        this.isLoading.set(false);
      },
    });
  }

  protected addTech(): void {
    const tech = this.newTech().trim();
    if (!tech) {
      return;
    }

    const current: string[] = this.projectForm.get('tech_stack')?.value || [];
    if (!current.includes(tech)) {
      this.projectForm.patchValue({ tech_stack: [...current, tech] });
    }
    this.newTech.set('');
  }

  protected removeTech(techToRemove: string): void {
    const current: string[] = this.projectForm.get('tech_stack')?.value || [];
    this.projectForm.patchValue({
      tech_stack: current.filter((t) => t !== techToRemove),
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
    return this.projectForm.get('tech_stack')?.value || [];
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
      this.showNotification('Please fill in all required fields', 'error');
      return;
    }

    this.isSaving.set(true);
    const formValue = this.projectForm.value;

    if (this.isNewProject()) {
      const request: ApiCreateProjectRequest = {
        title: formValue.title,
        slug: formValue.slug,
        description: formValue.description,
        long_description: formValue.long_description || undefined,
        tech_stack: formValue.tech_stack,
        role: formValue.role,
        highlights: formValue.highlights,
        github_url: formValue.github_url || undefined,
        live_url: formValue.live_url || undefined,
        featured: formValue.featured,
        sort_order: formValue.sort_order,
        status: formValue.status,
      };

      this.projectService.createProject(request).subscribe({
        next: () => {
          this.showNotification('Project created!', 'success');
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.showNotification('Failed to create', 'error');
          this.isSaving.set(false);
        },
      });
    } else {
      const request: ApiUpdateProjectRequest = {
        title: formValue.title,
        slug: formValue.slug,
        description: formValue.description,
        long_description: formValue.long_description || undefined,
        tech_stack: formValue.tech_stack,
        role: formValue.role,
        highlights: formValue.highlights,
        github_url: formValue.github_url || undefined,
        live_url: formValue.live_url || undefined,
        featured: formValue.featured,
        sort_order: formValue.sort_order,
        status: formValue.status,
      };

      this.projectService.updateProject(this.projectId!, request).subscribe({
        next: () => {
          this.showNotification('Project updated!', 'success');
          this.isSaving.set(false);
          this.router.navigate(['/admin']);
        },
        error: () => {
          this.showNotification('Failed to update', 'error');
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
