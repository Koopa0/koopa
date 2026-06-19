export { LoadingSpinnerComponent } from './loading-spinner/loading-spinner.component';
export { StatusBadgeComponent } from './status-badge/status-badge.component';
export { EmptyStateComponent } from './empty-state/empty-state.component';
export { ModalComponent } from './modal/modal.component';
export { FormFieldComponent } from './form-field/form-field.component';
export { DataTableComponent } from './data-table/data-table.component';
export { EnergyMeterComponent } from './energy-meter/energy-meter.component';

/* ── DS core primitives (Claude Design "koopa.dev Design System" ingest) ── */
export {
  ButtonComponent,
  type ButtonVariant,
  type ButtonSize,
} from './button/button.component';
export { BadgeComponent, type BadgeTone } from './badge/badge.component';
export {
  CalloutComponent,
  type CalloutVariant,
} from './callout/callout.component';
export { AlertComponent, type AlertVariant } from './alert/alert.component';
export { TabsComponent, type TabItem } from './tabs/tabs.component';

/* nav */
export {
  SegmentedComponent,
  type SegmentedItem,
} from './segmented/segmented.component';
export {
  BreadcrumbsComponent,
  type BreadcrumbItem,
} from './breadcrumbs/breadcrumbs.component';
export { PaginationComponent } from './pagination/pagination.component';
export { NavItemComponent } from './nav-item/nav-item.component';

/* cards / data display */
export {
  StatCardComponent,
  type StatTrend,
} from './stat-card/stat-card.component';
export {
  AvatarComponent,
  type AvatarSize,
  type AvatarActor,
} from './avatar/avatar.component';
export { AvatarGroupComponent } from './avatar-group/avatar-group.component';
export {
  ProgressComponent,
  type ProgressTone,
} from './progress/progress.component';
export { HextileComponent } from './hextile/hextile.component';

/* more */
export { AccordionComponent } from './accordion/accordion.component';
export { AccordionItemComponent } from './accordion-item/accordion-item.component';
export {
  DescriptionListComponent,
  type DescriptionRow,
} from './description-list/description-list.component';
export { StepperComponent, type StepItem } from './stepper/stepper.component';
export {
  SeparatorComponent,
  type SeparatorOrientation,
} from './separator/separator.component';

/* forms */
export { InputComponent, type InputSize } from './input/input.component';
export {
  TextareaComponent,
  type TextareaSize,
} from './textarea/textarea.component';
export {
  SelectComponent,
  type SelectOption,
  type SelectSize,
} from './select/select.component';
export { CheckboxComponent } from './checkbox/checkbox.component';
export { RadioComponent } from './radio/radio.component';
export { SwitchComponent } from './switch/switch.component';

/* small inline */
export { ChipComponent } from './chip/chip.component';
export { TagComponent } from './tag/tag.component';
export { KbdComponent } from './kbd/kbd.component';

/* overlays (CDK) */
export { MenuComponent } from './menu/menu.component';
export {
  MenuItemComponent,
  type MenuItemVariant,
} from './menu-item/menu-item.component';
export {
  TooltipDirective,
  TooltipComponent,
} from './tooltip/tooltip.directive';
export { DrawerComponent } from './drawer/drawer.component';

/* koopa pack */
export {
  ContentTypeComponent,
  type ContentType,
} from './content-type/content-type.component';

/* interactive — toast & command palette already exist under src/app/shared/
   (app-wired); only the new, non-duplicated code block ships from here. */
export { CodeBlockComponent } from './code-block/code-block.component';
