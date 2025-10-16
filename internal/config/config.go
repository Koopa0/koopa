package config

import (
	"os"
	"path/filepath"

	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/spf13/viper"
)

// Config 存儲應用配置
type Config struct {
	// AI 配置
	ModelName   string
	Temperature float32
	MaxTokens   int

	// 儲存配置
	DatabasePath string

	// API Keys
	GeminiAPIKey string
}

// Load 載入配置
// 優先順序：環境變數 > 配置文件 > 預設值
func Load() (*Config, error) {
	// 配置目錄: ~/.koopa/
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(home, ".koopa")

	// 確保目錄存在
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, err
	}

	// 設定 Viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".") // 也支援當前目錄

	// 設定預設值
	viper.SetDefault("model_name", "gemini-2.5-flash")
	viper.SetDefault("temperature", 0.7)
	viper.SetDefault("max_tokens", 2048)
	viper.SetDefault("database_path", filepath.Join(configDir, "koopa.db"))

	// 讀取配置檔案（如果存在）
	if err := viper.ReadInConfig(); err != nil {
		// 配置文件不存在不算錯誤，使用預設值
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	// 環境變數優先
	viper.AutomaticEnv()
	if err := viper.BindEnv("gemini_api_key", "GEMINI_API_KEY"); err != nil {
		return nil, err
	}

	// 構建 Config
	cfg := &Config{
		ModelName:    viper.GetString("model_name"),
		Temperature:  float32(viper.GetFloat64("temperature")),
		MaxTokens:    viper.GetInt("max_tokens"),
		DatabasePath: viper.GetString("database_path"),
		GeminiAPIKey: viper.GetString("gemini_api_key"),
	}

	return cfg, nil
}

// GetPlugins 返回 Genkit plugins
func (c *Config) GetPlugins() []any {
	return []any{&googlegenai.GoogleAI{}}
}

// Validate 驗證配置
func (c *Config) Validate() error {
	if c.GeminiAPIKey == "" {
		return &ConfigError{
			Field:   "GEMINI_API_KEY",
			Message: "Gemini API key is required. Set GEMINI_API_KEY environment variable or add it to config file.",
		}
	}
	return nil
}

// ConfigError 配置錯誤
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
