package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// ImageInput 圖片輸入結構
type ImageInput struct {
	ImagePath string `json:"image_path"`
	Prompt    string `json:"prompt"`
}

// createImagePart 讀取圖片檔案並創建 ai.Part
// 這個輔助函式封裝了「讀取檔案 -> 判斷 media type -> base64 編碼」的通用邏輯
func createImagePart(imagePath string) (*ai.Part, error) {
	// 讀取圖片檔案
	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, fmt.Errorf("無法讀取圖片 %s: %w", imagePath, err)
	}

	// 判斷圖片類型
	ext := strings.ToLower(filepath.Ext(imagePath))
	var mediaType string
	switch ext {
	case ".jpg", ".jpeg":
		mediaType = "image/jpeg"
	case ".png":
		mediaType = "image/png"
	case ".gif":
		mediaType = "image/gif"
	case ".webp":
		mediaType = "image/webp"
	default:
		return nil, fmt.Errorf("不支援的圖片格式: %s", ext)
	}

	// 將圖片轉換為 base64
	base64Image := base64.StdEncoding.EncodeToString(imageData)

	return ai.NewMediaPart(mediaType, "data:"+mediaType+";base64,"+base64Image), nil
}

// analyzeImage 分析圖片內容
func (a *Agent) AnalyzeImage(ctx context.Context, imagePath string, prompt string) (string, error) {
	// 使用輔助函式創建圖片 Part
	imagePart, err := createImagePart(imagePath)
	if err != nil {
		return "", err
	}

	// 構建包含圖片的訊息
	userMessage := ai.NewUserMessage(
		imagePart,
		ai.NewTextPart(prompt),
	)

	// 生成回應
	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(
			a.systemMessage,
			userMessage,
		),
	)
	if err != nil {
		return "", fmt.Errorf("生成回應失敗: %w", err)
	}

	return response.Text(), nil
}

// AnalyzeMultipleImages 分析多張圖片
func (a *Agent) AnalyzeMultipleImages(ctx context.Context, imagePaths []string, prompt string) (string, error) {
	if len(imagePaths) == 0 {
		return "", fmt.Errorf("未提供任何圖片")
	}

	// 構建包含多個圖片的 parts
	parts := make([]*ai.Part, 0, len(imagePaths)+1)

	// 添加所有圖片，使用輔助函式
	for i, imagePath := range imagePaths {
		imagePart, err := createImagePart(imagePath)
		if err != nil {
			return "", fmt.Errorf("處理第 %d 張圖片失敗: %w", i+1, err)
		}
		parts = append(parts, imagePart)
	}

	// 添加文字提示
	parts = append(parts, ai.NewTextPart(prompt))

	// 創建用戶訊息
	userMessage := ai.NewUserMessage(parts...)

	// 生成回應
	response, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(
			a.systemMessage,
			userMessage,
		),
	)
	if err != nil {
		return "", fmt.Errorf("生成回應失敗: %w", err)
	}

	return response.Text(), nil
}

// CompareImages 比較兩張圖片
func (a *Agent) CompareImages(ctx context.Context, imagePath1, imagePath2 string) (string, error) {
	return a.AnalyzeMultipleImages(ctx, []string{imagePath1, imagePath2},
		"請比較這兩張圖片，描述它們的相似點和不同點。")
}

// OCRImage 從圖片中提取文字（OCR）
func (a *Agent) OCRImage(ctx context.Context, imagePath string) (string, error) {
	return a.AnalyzeImage(ctx, imagePath,
		"請提取這張圖片中的所有文字內容，保持原有格式。")
}

// DescribeImage 描述圖片內容
func (a *Agent) DescribeImage(ctx context.Context, imagePath string) (string, error) {
	return a.AnalyzeImage(ctx, imagePath,
		"請詳細描述這張圖片的內容，包括主要物件、場景、顏色和氛圍。")
}

// AnalyzeScreenshot 分析螢幕截圖（適合 UI/UX 分析）
type ScreenshotAnalysis struct {
	UIElements   []string `json:"ui_elements"`
	Layout       string   `json:"layout"`
	ColorScheme  string   `json:"color_scheme"`
	Suggestions  []string `json:"suggestions"`
	Accessibility []string `json:"accessibility"`
}

func (a *Agent) AnalyzeScreenshot(ctx context.Context, screenshotPath string) (*ScreenshotAnalysis, error) {
	// 使用輔助函式創建圖片 Part
	imagePart, err := createImagePart(screenshotPath)
	if err != nil {
		return nil, fmt.Errorf("處理截圖失敗: %w", err)
	}

	userMessage := ai.NewUserMessage(
		imagePart,
		ai.NewTextPart("請分析這個螢幕截圖的 UI/UX 設計，包括元素、佈局、配色方案、改進建議和無障礙性。"),
	)

	// 使用 Generate 並傳遞圖片
	resp, err := genkit.Generate(ctx, a.genkitInstance,
		ai.WithModel(a.modelRef),
		ai.WithMessages(
			a.systemMessage,
			userMessage,
		),
		ai.WithOutputType(ScreenshotAnalysis{}),
	)
	if err != nil {
		return nil, fmt.Errorf("生成分析失敗: %w", err)
	}

	var analysis ScreenshotAnalysis
	if err := resp.Output(&analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}
