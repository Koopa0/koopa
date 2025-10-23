package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathValidator 路徑驗證器
// 用於防止路徑遍歷攻擊（CWE-22）
type PathValidator struct {
	allowedDirs []string
	workDir     string
}

// NewPathValidator 創建路徑驗證器
// allowedDirs: 允許訪問的目錄列表（空列表表示只允許工作目錄）
func NewPathValidator(allowedDirs []string) (*PathValidator, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("無法獲取工作目錄: %w", err)
	}

	// 將所有允許的目錄轉換為絕對路徑
	absAllowedDirs := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("無法解析目錄 %s: %w", dir, err)
		}
		absAllowedDirs = append(absAllowedDirs, absDir)
	}

	return &PathValidator{
		allowedDirs: absAllowedDirs,
		workDir:     workDir,
	}, nil
}

// ValidatePath 驗證並清理文件路徑
// 返回安全的絕對路徑，或返回錯誤
func (v *PathValidator) ValidatePath(path string) (string, error) {
	// 1. 清理路徑（移除 ../ 等）
	cleanPath := filepath.Clean(path)

	// 2. 轉換為絕對路徑
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("無效的路徑: %w", err)
	}

	// 3. 檢查是否在允許的目錄內
	allowed := false

	// 首先檢查工作目錄
	if strings.HasPrefix(absPath, v.workDir) {
		allowed = true
	}

	// 然後檢查額外的允許目錄
	if !allowed {
		for _, dir := range v.allowedDirs {
			if strings.HasPrefix(absPath, dir) {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		return "", fmt.Errorf("拒絕訪問: 路徑 '%s' 不在允許的目錄內", absPath)
	}

	// 4. 解析符號連結（防止通過符號連結繞過限制）
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// 如果文件不存在，EvalSymlinks 會失敗
		// 這對於創建新文件是可以接受的
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("無法解析符號連結: %w", err)
		}
		// 文件不存在，但路徑是安全的
		return absPath, nil
	}

	// 5. 再次檢查符號連結解析後的路徑是否在允許的目錄內
	if realPath != absPath {
		if !strings.HasPrefix(realPath, v.workDir) {
			inAllowedDir := false
			for _, dir := range v.allowedDirs {
				if strings.HasPrefix(realPath, dir) {
					inAllowedDir = true
					break
				}
			}
			if !inAllowedDir {
				return "", fmt.Errorf("拒絕訪問: 符號連結指向不允許的位置 '%s'", realPath)
			}
		}
		absPath = realPath
	}

	return absPath, nil
}

// IsPathSafe 快速檢查路徑是否包含明顯的危險模式
// 這是一個額外的保護層，但不應該單獨依賴
func IsPathSafe(path string) bool {
	// 檢查常見的危險模式
	dangerousPatterns := []string{
		"../",      // 向上遍歷
		"..\\",     // Windows 向上遍歷
		"/etc/",    // 系統配置
		"/dev/",    // 設備文件
		"/proc/",   // 進程信息
		"/sys/",    // 系統信息
		"c:\\",     // Windows 系統根目錄
		"c:/",      // Windows 系統根目錄
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	return true
}

// GetHomeDir 安全地獲取用戶主目錄
func GetHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("無法獲取用戶主目錄: %w", err)
	}
	return home, nil
}
