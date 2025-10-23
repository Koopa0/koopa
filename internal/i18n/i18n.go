package i18n

import (
	"fmt"
	"os"
	"strings"
)

// Supported languages
const (
	LangEN   = "en"
	LangZhTW = "zh-TW"
	LangJA   = "ja" // Reserved for future
)

// currentLang holds the current language setting
var currentLang = LangEN

// messages stores all translations
var messages = make(map[string]map[string]string)

// Init initializes the i18n system with the specified language
func Init(lang string) {
	// Normalize language code
	lang = strings.ToLower(strings.TrimSpace(lang))

	// Map common variations
	switch lang {
	case "en", "en-us", "english":
		currentLang = LangEN
	case "zh-tw", "zh_tw", "zh-hant", "chinese", "traditional chinese":
		currentLang = LangZhTW
	case "ja", "jp", "japanese":
		currentLang = LangJA
	default:
		// Check environment variable
		if envLang := os.Getenv("KOOPA_LANG"); envLang != "" {
			Init(envLang)
			return
		}
		// Default to English
		currentLang = LangEN
	}

	// Load messages
	loadMessages()
}

// SetLanguage changes the current language
func SetLanguage(lang string) {
	Init(lang)
}

// GetLanguage returns the current language
func GetLanguage() string {
	return currentLang
}

// T returns the translated message for the given key
// Falls back to English if translation is not found
func T(key string) string {
	if msg, ok := messages[currentLang][key]; ok {
		return msg
	}

	// Fallback to English
	if msg, ok := messages[LangEN][key]; ok {
		return msg
	}

	// Return key if no translation found
	return key
}

// Sprintf returns the translated and formatted message
func Sprintf(key string, args ...interface{}) string {
	return fmt.Sprintf(T(key), args...)
}

// loadMessages initializes the message maps
func loadMessages() {
	// Initialize maps
	messages[LangEN] = make(map[string]string)
	messages[LangZhTW] = make(map[string]string)
	messages[LangJA] = make(map[string]string)

	// Load English messages
	loadEnglishMessages()

	// Load Traditional Chinese messages
	loadChineseMessages()

	// Load Japanese messages (reserved for future)
	// loadJapaneseMessages()
}

// GetSupportedLanguages returns a list of supported language codes
func GetSupportedLanguages() []string {
	return []string{LangEN, LangZhTW}
}

// IsLanguageSupported checks if a language is supported
func IsLanguageSupported(lang string) bool {
	lang = strings.ToLower(strings.TrimSpace(lang))
	for _, supported := range GetSupportedLanguages() {
		if strings.EqualFold(lang, supported) {
			return true
		}
	}
	return false
}

// init is called automatically when the package is imported
func init() {
	// Check environment variable on startup
	if envLang := os.Getenv("KOOPA_LANG"); envLang != "" {
		Init(envLang)
	} else {
		Init(LangEN) // Default to English
	}
}
