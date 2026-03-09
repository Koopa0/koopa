# Flutter 狀態管理：Riverpod vs Bloc 完整比較

## 狀態管理的重要性

在 Flutter 應用開發中，選擇合適的狀態管理方案對應用的可維護性和性能至關重要。

## Riverpod 簡介

Riverpod 是 Provider 的重新設計版本，提供了更安全、更靈活的狀態管理方案。

### Riverpod 基本用法

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';

// 定義 Provider
final counterProvider = StateProvider<int>((ref) => 0);

// 在 Widget 中使用
class CounterWidget extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final count = ref.watch(counterProvider);

    return Column(
      children: [
        Text('Count: $count'),
        ElevatedButton(
          onPressed: () => ref.read(counterProvider.notifier).state++,
          child: Text('Increment'),
        ),
      ],
    );
  }
}
```

### Riverpod 進階用法

```dart
// AsyncProvider 處理異步數據
final userProvider = FutureProvider<User>((ref) async {
  final api = ref.read(apiProvider);
  return api.fetchUser();
});

// 組合 Provider
final filteredTodosProvider = Provider<List<Todo>>((ref) {
  final todos = ref.watch(todosProvider);
  final filter = ref.watch(filterProvider);

  return todos.where((todo) => filter.apply(todo)).toList();
});
```

## Bloc 簡介

Bloc (Business Logic Component) 基於流和響應式編程，提供了清晰的狀態管理架構。

### Bloc 基本用法

```dart
// 定義事件
abstract class CounterEvent {}
class Increment extends CounterEvent {}
class Decrement extends CounterEvent {}

// 定義 Bloc
class CounterBloc extends Bloc<CounterEvent, int> {
  CounterBloc() : super(0) {
    on<Increment>((event, emit) => emit(state + 1));
    on<Decrement>((event, emit) => emit(state - 1));
  }
}

// 在 Widget 中使用
class CounterWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return BlocBuilder<CounterBloc, int>(
      builder: (context, count) {
        return Column(
          children: [
            Text('Count: $count'),
            ElevatedButton(
              onPressed: () => context.read<CounterBloc>().add(Increment()),
              child: Text('Increment'),
            ),
          ],
        );
      },
    );
  }
}
```

### Cubit 簡化版本

```dart
class CounterCubit extends Cubit<int> {
  CounterCubit() : super(0);

  void increment() => emit(state + 1);
  void decrement() => emit(state - 1);
}
```

## 詳細比較

### 學習曲線
- **Riverpod**: 中等，概念相對簡單
- **Bloc**: 較陡峭，需要理解流和響應式編程

### 程式碼簡潔性
- **Riverpod**: 更簡潔，較少樣板代碼
- **Bloc**: 較多樣板代碼，但結構清晰

### 測試支援
- **Riverpod**: 優秀，容易模擬和測試
- **Bloc**: 優秀，內建測試支援

### 社群生態
- **Riverpod**: 快速增長，現代化
- **Bloc**: 成熟穩定，廣泛使用

## 選擇建議

### 選擇 Riverpod 當：
- 團隊偏好簡潔的 API
- 需要快速開發
- 應用狀態相對簡單

### 選擇 Bloc 當：
- 團隊熟悉響應式編程
- 需要嚴格的狀態管理規範
- 複雜的業務邏輯

## 最佳實踐

### Riverpod 最佳實踐
1. 使用 `ref.watch` 監聽變化
2. 使用 `ref.read` 觸發一次性操作
3. 合理組合 Provider
4. 使用 `autoDispose` 管理生命週期

### Bloc 最佳實踐
1. 保持事件和狀態的不可變性
2. 使用 `BlocListener` 處理副作用
3. 合理分割 Bloc 職責
4. 使用 `MultiBlocProvider` 組織 Bloc

## 總結

Riverpod 和 Bloc 都是優秀的狀態管理方案。選擇哪一個主要取決於團隊的偏好和專案需求。
