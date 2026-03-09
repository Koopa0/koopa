import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { TagService } from './tag.service';

describe('TagService', () => {
  let service: TagService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TagService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should have tag list initialized', () => {
    const tags = service.tagList();
    expect(tags.length).toBeGreaterThan(0);
  });

  it('should return popular tags sorted by article count descending', () => {
    const popular = service.popularTags();
    expect(popular.length).toBeGreaterThan(0);
    expect(popular.every((t) => t.articleCount > 0)).toBe(true);

    for (let i = 1; i < popular.length; i++) {
      expect(popular[i].articleCount).toBeLessThanOrEqual(
        popular[i - 1].articleCount,
      );
    }
  });

  it('should return tag cloud with weights', () => {
    const cloud = service.tagCloud();
    expect(cloud.length).toBeGreaterThan(0);
    expect(cloud.every((c) => c.weight >= 1 && c.weight <= 6)).toBe(true);
  });

  it('should get all tags via observable', async () => {
    const tags = await firstValueFrom(service.getAllTags());
    expect(tags.length).toBeGreaterThan(0);
  });

  it('should find tag by slug', async () => {
    const tags = service.tagList();
    const first = tags[0];
    const found = await firstValueFrom(service.getTagBySlug(first.slug));
    expect(found).toBeDefined();
    expect(found!.name).toBe(first.name);
  });

  it('should return null for unknown slug', async () => {
    const found = await firstValueFrom(service.getTagBySlug('unknown-slug'));
    expect(found).toBeNull();
  });

  it('should search tags by name', async () => {
    const tags = service.tagList();
    const firstName = tags[0].name;
    const results = await firstValueFrom(service.searchTags(firstName));
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((t) => t.name === firstName)).toBe(true);
  });

  it('should return empty array for non-matching search', async () => {
    const results = await firstValueFrom(service.searchTags('xyznonexistent'));
    expect(results).toEqual([]);
  });
});
