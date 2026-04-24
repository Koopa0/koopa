# Angular Signals: 完整指南與最佳實踐

## 什麼是 Angular Signals？

Angular Signals 是 Angular 20+ 中引入的新響應式編程范式，它提供了一種更簡潔、更高效的狀態管理方式。

## 基本用法

```typescript
import { signal, computed, effect } from '@angular/core';

// 創建一個信號
const count = signal(0);

// 讀取信號值
console.log(count()); // 0

// 更新信號值
count.set(10);
count.update(value => value + 1);
```

## 計算信號 (Computed Signals)

```typescript
const count = signal(0);
const doubledCount = computed(() => count() * 2);

console.log(doubledCount()); // 0
count.set(5);
console.log(doubledCount()); // 10
```

## 效果 (Effects)

```typescript
const count = signal(0);

effect(() => {
  console.log('計數變更:', count());
});

count.set(5); // 輸出: "計數變更: 5"
```

## 最佳實踐

1. **使用 Signals 進行狀態管理**
2. **避免在迴圈中創建 Signals**
3. **合理使用 Effects**
4. **保持 OnPush 變更檢測策略**

## 總結

Angular Signals 為現代 Angular 應用提供了強大而高效的響應式編程能力。
