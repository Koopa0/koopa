# Golang 併發編程：Goroutines 與 Channels 深度解析

## Go 併發模型概述

Go 語言的併發模型基於 CSP (Communicating Sequential Processes) 理論，通過 goroutines 和 channels 實現優雅的併發編程。

## Goroutines 基礎

```go
package main

import (
    "fmt"
    "time"
)

func worker(id int) {
    fmt.Printf("Worker %d starting\n", id)
    time.Sleep(time.Second)
    fmt.Printf("Worker %d done\n", id)
}

func main() {
    for i := 1; i <= 5; i++ {
        go worker(i)
    }

    time.Sleep(time.Second * 2)
}
```

## Channels 通信

```go
func main() {
    ch := make(chan string)

    go func() {
        ch <- "Hello from goroutine"
    }()

    message := <-ch
    fmt.Println(message)
}
```

## 緩衝 Channels

```go
ch := make(chan int, 3) // 緩衝區大小為 3

ch <- 1
ch <- 2
ch <- 3
// 不會阻塞，因為緩衝區未滿
```

## Select 語句

```go
select {
case msg1 := <-ch1:
    fmt.Println("Received from ch1:", msg1)
case msg2 := <-ch2:
    fmt.Println("Received from ch2:", msg2)
case <-time.After(1 * time.Second):
    fmt.Println("Timeout")
}
```

## 併發模式

### Worker Pool

```go
func workerPool(jobs <-chan int, results chan<- int) {
    for job := range jobs {
        results <- job * 2
    }
}

func main() {
    jobs := make(chan int, 100)
    results := make(chan int, 100)

    // 啟動 3 個 worker
    for w := 1; w <= 3; w++ {
        go workerPool(jobs, results)
    }

    // 發送工作
    for j := 1; j <= 5; j++ {
        jobs <- j
    }
    close(jobs)

    // 收集結果
    for a := 1; a <= 5; a++ {
        <-results
    }
}
```

## 最佳實踐

1. **避免 goroutine 洩漏**
2. **適當使用緩衝 channels**
3. **使用 context 進行取消操作**
4. **避免共享記憶體，使用通信**

## 總結

Go 的併發模型提供了簡潔而強大的併發編程能力，掌握 goroutines 和 channels 是成為 Go 高手的必經之路。
