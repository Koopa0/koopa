import { TestBed } from '@angular/core/testing';
import { AdminTopbarService } from './admin-topbar.service';

describe('AdminTopbarService', () => {
  let service: AdminTopbarService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AdminTopbarService);
  });

  it('should normalize omitted optional fields to empty arrays when set', () => {
    service.set({ title: 'Notes' });

    const ctx = service.context();
    expect(ctx.title).toBe('Notes');
    expect(ctx.crumbs).toEqual([]);
    expect(ctx.actions).toEqual([]);
    expect(ctx.overflowActions).toEqual([]);
  });

  it('should keep provided crumbs and actions when set', () => {
    const run = () => undefined;
    service.set({
      title: 'Content',
      crumbs: ['knowledge', 'content'],
      actions: [{ id: 'save', label: 'Save', run }],
    });

    const ctx = service.context();
    expect(ctx.crumbs).toEqual(['knowledge', 'content']);
    expect(ctx.actions?.map((a) => a.id)).toEqual(['save']);
  });

  it('should restore the default empty context when reset', () => {
    service.set({ title: 'Content', crumbs: ['knowledge'] });
    service.reset();

    const ctx = service.context();
    expect(ctx.title).toBe('');
    expect(ctx.crumbs).toEqual([]);
  });
});
