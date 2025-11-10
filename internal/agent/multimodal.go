package agent

// multimodal.go implements vision and multimodal capabilities for the Agent.
//
// Provides image analysis methods:
//   - Base: AnalyzeImage (single), AnalyzeMultipleImages (multiple with custom prompts)
//   - Specialized: OCRImage, CompareImages, DescribeImage, AnalyzeScreenshot (structured UI/UX output)
//
// Security: All paths validated via pathValidator (CWE-22). Content type detected via http.DetectContentType
// (magic bytes, not extension). Supports: jpg/jpeg, png, gif, webp. Uses Genkit's ai.Part for multimodal.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/security"
)

// ImageInput image input structure
type ImageInput struct {
	ImagePath string `json:"image_path"`
	Prompt    string `json:"prompt"`
}

// createImagePart reads an image file and creates an ai.Part
// This is a standalone helper function following Go best practices
// pathValidator is passed as parameter for explicit dependency and better testability
func createImagePart(pathValidator *security.Path, imagePath string) (*ai.Part, error) {
	// Path security validation (prevent path traversal attacks CWE-22)
	safePath, err := pathValidator.ValidatePath(imagePath)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// Read image file
	imageData, err := os.ReadFile(safePath) // #nosec G304 -- path validated by pathValidator above
	if err != nil {
		return nil, fmt.Errorf("unable to read image %s: %w", safePath, err)
	}

	// Determine image type using http.DetectContentType (more robust, checks actual content)
	// This is safer than relying solely on file extension which can be spoofed
	mediaType := http.DetectContentType(imageData)

	// Verify it's actually an image MIME type
	if !strings.HasPrefix(mediaType, "image/") {
		// Fallback: check file extension as a secondary validation
		ext := strings.ToLower(filepath.Ext(safePath))
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
			return nil, fmt.Errorf("file is not a valid image (detected: %s, extension: %s)", mediaType, ext)
		}
	}

	// Convert image to base64
	base64Image := base64.StdEncoding.EncodeToString(imageData)

	return ai.NewMediaPart(mediaType, "data:"+mediaType+";base64,"+base64Image), nil
}

// AnalyzeImage analyzes image content
func (a *Agent) AnalyzeImage(ctx context.Context, imagePath string, prompt string) (string, error) {
	// Use helper function to create image Part
	imagePart, err := createImagePart(a.pathValidator, imagePath)
	if err != nil {
		return "", err
	}

	// Build message containing image
	userMessage := ai.NewUserMessage(
		imagePart,
		ai.NewTextPart(prompt),
	)

	// Generate response
	response, err := genkit.Generate(ctx, a.Genkit,
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(userMessage),
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate response: %w", err)
	}

	return response.Text(), nil
}

// AnalyzeMultipleImages analyzes multiple images
func (a *Agent) AnalyzeMultipleImages(ctx context.Context, imagePaths []string, prompt string) (string, error) {
	if len(imagePaths) == 0 {
		return "", fmt.Errorf("no images provided")
	}

	// Build parts containing multiple images
	parts := make([]*ai.Part, 0, len(imagePaths)+1)

	// Add all images using helper function
	for i, imagePath := range imagePaths {
		imagePart, err := createImagePart(a.pathValidator, imagePath)
		if err != nil {
			return "", fmt.Errorf("failed to process image %d: %w", i+1, err)
		}
		parts = append(parts, imagePart)
	}

	// Add text prompt
	parts = append(parts, ai.NewTextPart(prompt))

	// Create user message
	userMessage := ai.NewUserMessage(parts...)

	// Generate response
	response, err := genkit.Generate(ctx, a.Genkit,
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(userMessage),
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate response: %w", err)
	}

	return response.Text(), nil
}

// CompareImages compares two images
func (a *Agent) CompareImages(ctx context.Context, imagePath1, imagePath2 string) (string, error) {
	return a.AnalyzeMultipleImages(ctx, []string{imagePath1, imagePath2},
		"Please compare these two images and describe their similarities and differences.")
}

// OCRImage extracts text from an image (OCR)
func (a *Agent) OCRImage(ctx context.Context, imagePath string) (string, error) {
	return a.AnalyzeImage(ctx, imagePath,
		"Please extract all text content from this image, maintaining the original format.")
}

// DescribeImage describes image content
func (a *Agent) DescribeImage(ctx context.Context, imagePath string) (string, error) {
	return a.AnalyzeImage(ctx, imagePath,
		"Please describe this image in detail, including main objects, scenes, colors, and atmosphere.")
}

// AnalyzeScreenshot analyzes a screenshot (suitable for UI/UX analysis)
type ScreenshotAnalysis struct {
	UIElements    []string `json:"ui_elements"`
	Layout        string   `json:"layout"`
	ColorScheme   string   `json:"color_scheme"`
	Suggestions   []string `json:"suggestions"`
	Accessibility []string `json:"accessibility"`
}

func (a *Agent) AnalyzeScreenshot(ctx context.Context, screenshotPath string) (*ScreenshotAnalysis, error) {
	// Use helper function to create image Part
	imagePart, err := createImagePart(a.pathValidator, screenshotPath)
	if err != nil {
		return nil, fmt.Errorf("failed to process screenshot: %w", err)
	}

	userMessage := ai.NewUserMessage(
		imagePart,
		ai.NewTextPart("Please analyze this screenshot's UI/UX design, including elements, layout, color scheme, improvement suggestions, and accessibility."),
	)

	// Use Generate and pass image
	resp, err := genkit.Generate(ctx, a.Genkit,
		ai.WithModel(a.modelRef),
		ai.WithSystem(a.systemPrompt),
		ai.WithMessages(userMessage),
		ai.WithOutputType(ScreenshotAnalysis{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate analysis: %w", err)
	}

	var analysis ScreenshotAnalysis
	if err := resp.Output(&analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}
