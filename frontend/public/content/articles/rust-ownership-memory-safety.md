# Rust 所有權系統：記憶體安全的革命性方法

## 所有權系統概述

Rust 的所有權系統是其最獨特的特性，它在編譯時期保證記憶體安全，無需垃圾回收器。

## 所有權規則

1. Rust 中的每個值都有一個所有者
2. 在任何時刻，值只能有一個所有者
3. 當所有者離開作用域時，值會被丟棄

## 基本範例

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1; // s1 的所有權移轉給 s2

    // println!("{}", s1); // 編譯錯誤！s1 已不再擁有值
    println!("{}", s2); // 正確
}
```

## 借用 (Borrowing)

```rust
fn main() {
    let s1 = String::from("hello");

    let len = calculate_length(&s1); // 借用 s1

    println!("The length of '{}' is {}.", s1, len); // s1 仍然有效
}

fn calculate_length(s: &String) -> usize {
    s.len()
} // s 離開作用域，但因為它不擁有引用的值，所以什麼都不會發生
```

## 可變借用

```rust
fn main() {
    let mut s = String::from("hello");

    change(&mut s);

    println!("{}", s); // "hello, world"
}

fn change(some_string: &mut String) {
    some_string.push_str(", world");
}
```

## 借用規則

1. 在任何時刻，你可以有**要麼**一個可變引用，**要麼**任意數量的不可變引用
2. 引用必須總是有效的

## 生命週期

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}

fn main() {
    let string1 = String::from("long string is long");

    {
        let string2 = String::from("xyz");
        let result = longest(string1.as_str(), string2.as_str());
        println!("The longest string is {}", result);
    }
}
```

## 結構體中的生命週期

```rust
struct ImportantExcerpt<'a> {
    part: &'a str,
}

impl<'a> ImportantExcerpt<'a> {
    fn level(&self) -> i32 {
        3
    }

    fn announce_and_return_part(&self, announcement: &str) -> &str {
        println!("Attention please: {}", announcement);
        self.part
    }
}
```

## 智能指針

### Box<T>

```rust
fn main() {
    let b = Box::new(5);
    println!("b = {}", b);
}
```

### Rc<T> 引用計數

```rust
use std::rc::Rc;

fn main() {
    let a = Rc::new(5);
    let b = Rc::clone(&a);
    let c = Rc::clone(&a);

    println!("Reference count: {}", Rc::strong_count(&a)); // 3
}
```

## 最佳實踐

1. **優先使用借用而不是所有權轉移**
2. **儘量使用不可變引用**
3. **避免不必要的克隆**
4. **理解生命週期參數的意義**

## 總結

Rust 的所有權系統雖然學習曲線陡峭，但它提供了無與倫比的記憶體安全保證。掌握這些概念是成為 Rust 專家的關鍵。
