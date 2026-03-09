---
name: angular-forms
description: >-
  Angular typed Reactive Forms — validation, custom validators, accessible
  form controls, and Catalyst UI Kit form design reference.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Forms

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 建立或修改表單元件（Reactive Forms / Template-driven Forms）
- 實作表單驗證（內建或自定義驗證器）
- 建立表單相關的共用元件（Input / Select / Checkbox 等）
- 需要 Catalyst UI Kit 表單元件的設計參考
- 處理表單的無障礙（a11y）需求
- 使用 `/new-component` 建立表單元件

## Typed Reactive Forms

```typescript
import { FormControl, FormGroup, Validators } from '@angular/forms';

interface LoginForm {
  email: FormControl<string>;
  password: FormControl<string>;
  rememberMe: FormControl<boolean>;
}

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <form [formGroup]="form" (ngSubmit)="submit()">
      <label for="email">Email</label>
      <input id="email" formControlName="email" data-testid="email-input">

      <label for="password">Password</label>
      <input id="password" type="password" formControlName="password"
             data-testid="password-input">

      @if (form.controls.email.errors?.['required'] && form.controls.email.touched) {
        <p data-testid="email-error" role="alert">Email is required</p>
      }

      <button type="submit" [disabled]="form.invalid" data-testid="submit-button">
        Login
      </button>
    </form>
  `,
})
export class LoginComponent {
  protected readonly form = new FormGroup<LoginForm>({
    email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    password: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.minLength(8)],
    }),
    rememberMe: new FormControl(false, { nonNullable: true }),
  });

  protected submit(): void {
    if (this.form.valid) {
      const { email, password, rememberMe } = this.form.getRawValue();
      // 處理登入
    }
  }
}
```

## 驗證規範

- 所有表單控制項有 `<label>` 或 `aria-label`
- 錯誤訊息使用 `role="alert"`
- 使用 `nonNullable: true` 確保型別安全
- 使用 `data-testid` 便於測試

## 自定義驗證器

```typescript
export function matchFieldValidator(field: string): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const parent = control.parent;
    if (!parent) return null;

    const matchControl = parent.get(field);
    if (!matchControl) return null;

    return control.value === matchControl.value
      ? null
      : { matchField: { field } };
  };
}
```

## 設計參考資源

### Catalyst UI Kit 表單元件

從 `tailwind/css/catalyst-ui-kit/typescript/` 提取 HTML 結構與 Tailwind classes，轉換為 Angular standalone component。

| Catalyst 元件 | 檔案路徑 | Angular 用途 |
|---------------|---------|-------------|
| Input | `input.tsx` | 文字輸入框 |
| Checkbox | `checkbox.tsx` | 核取方塊 |
| Radio | `radio.tsx` | 單選按鈕 |
| Select | `select.tsx` | 下拉選擇 |
| Textarea | `textarea.tsx` | 多行輸入框 |
| Fieldset | `fieldset.tsx` | 表單欄位群組 |
| Combobox | `combobox.tsx` | 可搜尋下拉選單 |
| Listbox | `listbox.tsx` | 列表選擇 |

### UI Blocks 表單參考

| 區塊分類 | 路徑 | 說明 |
|---------|------|------|
| Input Groups | `ui-blocks/application-ui/forms/input-groups/` | 輸入群組佈局 |
| Checkboxes | `ui-blocks/application-ui/forms/checkboxes/` | 核取方塊群組 |
| Radio Groups | `ui-blocks/application-ui/forms/radio-groups/` | 單選按鈕群組 |
| Toggles | `ui-blocks/application-ui/forms/toggles/` | 開關切換 |
| Sign-in Forms | `ui-blocks/application-ui/forms/sign-in-and-registration/` | 登入/註冊表單 |

### Catalyst 表單元件 Angular 轉換範例

```typescript
// 從 Catalyst Input 轉換的 Angular 元件
@Component({
  selector: 'app-form-input',
  standalone: true,
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div data-testid="form-input-wrapper">
      @if (label()) {
        <label
          [for]="inputId()"
          class="block text-sm/6 font-medium text-zinc-950 dark:text-white"
          data-testid="form-input-label"
        >
          {{ label() }}
        </label>
      }
      <div class="mt-2">
        <input
          [id]="inputId()"
          [type]="type()"
          [formControl]="control()"
          [placeholder]="placeholder()"
          [attr.aria-describedby]="hasError() ? errorId() : null"
          [attr.aria-invalid]="hasError()"
          class="block w-full rounded-sm bg-white px-3 py-1.5
                 text-base text-zinc-950 outline-1 -outline-offset-1
                 outline-zinc-300 placeholder:text-zinc-400
                 focus:outline-2 focus:-outline-offset-2 focus:outline-zinc-950
                 dark:bg-white/5 dark:text-white dark:outline-white/10
                 dark:placeholder:text-zinc-500 dark:focus:outline-white
                 sm:text-sm/6"
          [attr.data-testid]="inputId() + '-input'"
        />
      </div>
      @if (hasError()) {
        <p
          [id]="errorId()"
          role="alert"
          class="mt-1 text-sm text-red-600 dark:text-red-400"
          [attr.data-testid]="inputId() + '-error'"
        >
          {{ errorMessage() }}
        </p>
      }
    </div>
  `,
})
export class FormInputComponent {
  readonly label = input<string>();
  readonly type = input<string>('text');
  readonly placeholder = input<string>('');
  readonly control = input.required<FormControl>();
  readonly inputId = input.required<string>();

  protected readonly hasError = computed(() => {
    const ctrl = this.control();
    return ctrl.invalid && ctrl.touched;
  });

  protected readonly errorId = computed(() => `${this.inputId()}-error`);

  protected readonly errorMessage = computed(() => {
    const errors = this.control().errors;
    if (!errors) return '';
    if (errors['required']) return '此欄位為必填';
    if (errors['email']) return '請輸入有效的 Email';
    if (errors['minlength']) {
      const requiredLength = errors['minlength'].requiredLength as number;
      return `最少需要 ${requiredLength} 個字元`;
    }
    return '輸入內容無效';
  });
}
```

### Tailwind v4 表單樣式注意事項

| v3（禁止） | v4（必須使用） | 說明 |
|-----------|--------------|------|
| `shadow-sm` | `shadow-xs` | 輸入框陰影 |
| `shadow` | `shadow-sm` | 卡片陰影 |
| `rounded-sm` | `rounded-xs` | 小圓角 |
| `rounded` | `rounded-sm` | 標準圓角 |
| `outline-none` | `outline-hidden` | 隱藏外框 |
| `ring` | `ring-3` | 焦點環 |
| `focus:ring-2 focus:ring-offset-2` | `focus:outline-2 focus:-outline-offset-2` | 焦點樣式 |

## 表單測試指引

### TestBed 表單測試範例

```typescript
// login.component.spec.ts
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { LoginComponent } from './login.component';

describe('LoginComponent', () => {
  let component: LoginComponent;
  let fixture: ComponentFixture<LoginComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginComponent],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('should have invalid form when empty', () => {
    expect(component['form'].valid).toBeFalsy();
  });

  it('should validate email field as required', () => {
    const emailControl = component['form'].controls.email;
    expect(emailControl.errors?.['required']).toBeTruthy();
  });

  it('should validate email format', () => {
    const emailControl = component['form'].controls.email;
    emailControl.setValue('invalid-email');
    expect(emailControl.errors?.['email']).toBeTruthy();

    emailControl.setValue('valid@example.com');
    expect(emailControl.errors).toBeNull();
  });

  it('should validate password minimum length', () => {
    const passwordControl = component['form'].controls.password;
    passwordControl.setValue('short');
    expect(passwordControl.errors?.['minlength']).toBeTruthy();

    passwordControl.setValue('validpassword123');
    expect(passwordControl.errors).toBeNull();
  });

  it('should enable submit button when form is valid', () => {
    component['form'].controls.email.setValue('user@example.com');
    component['form'].controls.password.setValue('validpassword123');
    fixture.detectChanges();

    const submitButton = fixture.nativeElement.querySelector(
      '[data-testid="submit-button"]',
    ) as HTMLButtonElement;
    expect(submitButton.disabled).toBeFalsy();
  });

  it('should show error message when email is touched and empty', () => {
    const emailControl = component['form'].controls.email;
    emailControl.markAsTouched();
    fixture.detectChanges();

    const errorElement = fixture.nativeElement.querySelector(
      '[data-testid="email-error"]',
    );
    expect(errorElement).toBeTruthy();
  });

  it('should disable submit button when form is invalid', () => {
    const submitButton = fixture.nativeElement.querySelector(
      '[data-testid="submit-button"]',
    ) as HTMLButtonElement;
    expect(submitButton.disabled).toBeTruthy();
  });
});
```

### 自定義驗證器測試

```typescript
// validators/match-field.validator.spec.ts
import { FormControl, FormGroup } from '@angular/forms';
import { matchFieldValidator } from './match-field.validator';

describe('matchFieldValidator', () => {
  let form: FormGroup;

  beforeEach(() => {
    form = new FormGroup({
      password: new FormControl(''),
      confirmPassword: new FormControl('', {
        validators: [matchFieldValidator('password')],
      }),
    });
  });

  it('should return null when fields match', () => {
    form.controls['password'].setValue('test123');
    form.controls['confirmPassword'].setValue('test123');
    expect(form.controls['confirmPassword'].errors).toBeNull();
  });

  it('should return error when fields do not match', () => {
    form.controls['password'].setValue('test123');
    form.controls['confirmPassword'].setValue('different');
    expect(form.controls['confirmPassword'].errors?.['matchField']).toBeTruthy();
  });
});
```

## 檢查清單

- [ ] 使用 Typed Reactive Forms（`FormGroup<T>` 搭配介面）
- [ ] 所有 `FormControl` 設定 `nonNullable: true`
- [ ] 每個表單欄位有關聯的 `<label>` 或 `aria-label`
- [ ] 錯誤訊息使用 `role="alert"` 以支援螢幕閱讀器
- [ ] 錯誤訊息透過 `aria-describedby` 連結到對應的輸入框
- [ ] 無效欄位設定 `aria-invalid="true"`
- [ ] 使用 `data-testid` 屬性便於測試選取
- [ ] 使用 Tailwind v4 語法（`shadow-xs`、`rounded-sm`、`outline-hidden`）
- [ ] 支援深色模式（`dark:` 前綴）
- [ ] 表單驗證邏輯有對應的單元測試
- [ ] 自定義驗證器有獨立的測試檔案
- [ ] 表單 DOM 互動有 TestBed 整合測試

## 參考資源

- [Angular Reactive Forms 指南](https://angular.dev/guide/forms/reactive-forms)
- [Angular 表單驗證](https://angular.dev/guide/forms/form-validation)
- [Angular Typed Forms](https://angular.dev/guide/forms/typed-forms)
- [Catalyst UI Kit 表單元件](tailwind/css/catalyst-ui-kit/typescript/) — Input / Checkbox / Radio / Select / Textarea / Fieldset
- [UI Blocks 表單區塊](tailwind/css/ui-blocks/application-ui/forms/)
- [Tailwind CSS v4 規則](tailwind/css/rules/tailwind.md)
- [WAI-ARIA 表單模式](https://www.w3.org/WAI/ARIA/apg/patterns/)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — input/output/model 函式型 API
- [coding-style](../angular-rules/references/coding-style.md) — 命名與格式規範
- [error-handling](../angular-rules/references/error-handling.md) — 表單驗證錯誤處理
