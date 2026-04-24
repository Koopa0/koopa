# Minimal Design System - zed.dev Inspired

This document outlines the minimal design system used in Koopa Blog, inspired by zed.dev's clean aesthetic.

## Core Principles

1. **No Shadows** - All `box-shadow` properties are set to `none`
2. **No Transforms** - No `translateY()` or `scale()` on hover/active states
3. **Subtle Borders** - 1px solid borders with muted colors
4. **Consistent Border Radius** - Small, medium, and large radius options
5. **Proper Dark Mode** - Clean contrast without excessive effects

## Button Styles

### Primary Button (Filled)
```scss
// Light mode
background: #0a0a0a;
color: #ffffff;
border: 1px solid transparent;

// Dark mode
background: #fafafa;
color: #0a0a0a;

// Hover state - subtle background change only
&:hover {
  background: #525252; // light mode
  background: #e5e5e5; // dark mode
}
```

### Secondary Button (Outlined)
```scss
// Light mode
background: transparent;
color: #0a0a0a;
border: 1px solid #e5e5e5;

// Dark mode
color: #fafafa;
border: 1px solid rgba(255, 255, 255, 0.1);

// Hover state - subtle background fill
&:hover {
  background: #fafafa; // light mode
  background: rgba(255, 255, 255, 0.05); // dark mode
  border-color: #d4d4d4; // light mode
  border-color: rgba(255, 255, 255, 0.2); // dark mode
}
```

### Ghost Button (Minimal)
```scss
background: transparent;
color: #525252;
border: 1px solid transparent;

&:hover {
  background: #fafafa;
  color: #0a0a0a;
}
```

## Card Styles

### Base Card
```scss
// Light mode
background: #ffffff;
border: 1px solid #e5e5e5;
border-radius: 8px;
box-shadow: none;

// Dark mode
background: #0a0a0a;
border: 1px solid rgba(255, 255, 255, 0.1);

// Hover state - border color change only
&:hover {
  border-color: #d4d4d4; // light mode
  border-color: rgba(255, 255, 255, 0.2); // dark mode
  // NO transform or shadow
}
```

### Elevated Card
```scss
// Same as base but with secondary background
background: #fafafa; // light mode
background: #171717; // dark mode
```

### Interactive Card
```scss
cursor: pointer;

&:hover {
  background: #fafafa; // light mode
  background: rgba(255, 255, 255, 0.02); // dark mode
}
```

## Color Palette

### Light Mode
- Background Primary: `#ffffff`
- Background Secondary: `#fafafa`
- Background Tertiary: `#f5f5f5`
- Text Primary: `#0a0a0a`
- Text Secondary: `#525252`
- Text Muted: `#737373`
- Border Default: `#e5e5e5`
- Border Hover: `#d4d4d4`
- Accent: `#2563eb`

### Dark Mode
- Background Primary: `#0a0a0a`
- Background Secondary: `#171717`
- Background Tertiary: `#1a1a1a`
- Text Primary: `#fafafa`
- Text Secondary: `#a3a3a3`
- Text Muted: `#737373`
- Border Default: `rgba(255, 255, 255, 0.1)`
- Border Hover: `rgba(255, 255, 255, 0.2)`
- Accent: `#3b82f6`

## Implementation

### Import the Minimal Component Styles
```scss
@import 'app/styles/minimal-components.scss';
```

### Usage Examples

#### Button
```html
<!-- Primary -->
<button mat-raised-button color="primary">Save</button>

<!-- Secondary -->
<button mat-stroked-button>Cancel</button>

<!-- Ghost -->
<button mat-button>Learn More</button>

<!-- Accent -->
<button mat-raised-button color="accent">Create New</button>
```

#### Card
```html
<!-- Base Card -->
<mat-card class="minimal-card">
  <mat-card-content>Content</mat-card-content>
</mat-card>

<!-- Elevated Card -->
<mat-card class="minimal-card--elevated">
  <mat-card-content>Content</mat-card-content>
</mat-card>

<!-- Interactive Card -->
<mat-card class="minimal-card--interactive" (click)="handleClick()">
  <mat-card-content>Clickable Content</mat-card-content>
</mat-card>
```

## Anti-Patterns to Avoid

1. **Don't use shadows**
   ```scss
   // BAD
   box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
   
   // GOOD
   box-shadow: none;
   ```

2. **Don't transform on hover**
   ```scss
   // BAD
   &:hover {
     transform: translateY(-2px);
   }
   
   // GOOD
   &:hover {
     // Use border or background changes only
   }
   ```

3. **Don't use gradients**
   ```scss
   // BAD
   background: linear-gradient(135deg, #2563eb, #1d4ed8);
   
   // GOOD
   background: #2563eb;
   ```

4. **Don't use thick borders**
   ```scss
   // BAD
   border: 2px solid #2563eb;
   
   // GOOD
   border: 1px solid #e5e5e5;
   ```

## Transitions

Keep transitions simple and fast:
```scss
transition: all 200ms ease-in-out;

// Or be specific
transition-property: background-color, border-color, color;
transition-duration: 200ms;
transition-timing-function: ease-in-out;
```

## Accessibility

- Maintain proper color contrast ratios
- Use focus-visible for keyboard navigation
- Never remove focus indicators
- Ensure interactive elements have proper hover/focus states

## Material Component Overrides

All Angular Material components are automatically styled with the minimal design system when you import `minimal-components.scss`. The system overrides:

- mat-button (all variants)
- mat-card
- mat-form-field
- mat-dialog
- mat-menu
- mat-snackbar
- mat-chip

No additional configuration needed!