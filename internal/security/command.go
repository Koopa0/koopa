package security

import (
	"fmt"
	"strings"
)

// CommandValidator 命令驗證器
// 用於防止命令注入攻擊（CWE-78）
type CommandValidator struct {
	blacklist []string
	whitelist []string // 如果非空，只允許白名單中的命令
}

// NewCommandValidator 創建命令驗證器
func NewCommandValidator() *CommandValidator {
	return &CommandValidator{
		blacklist: []string{
			// 危險的刪除命令
			"rm -rf /",
			"rm -rf ~",
			"rm -rf /*",
			"rm -rf $HOME",

			// 磁碟操作
			"dd if=/dev/zero",
			"dd if=/dev/urandom",
			"mkfs",
			"format",
			"fdisk",

			// 設備訪問
			"> /dev/",
			"< /dev/",

			// 遠程腳本執行
			"curl", // 需要特別處理
			"wget", // 需要特別處理

			// Fork 炸彈
			":()",
			"fork",

			// 系統關閉
			"shutdown",
			"reboot",
			"halt",
			"poweroff",

			// 權限提升
			"sudo su",
			"su -",
		},
	}
}

// NewStrictCommandValidator 創建嚴格的命令驗證器（白名單模式）
// 只允許常見的安全命令
func NewStrictCommandValidator() *CommandValidator {
	return &CommandValidator{
		blacklist: []string{}, // 白名單模式不需要黑名單
		whitelist: []string{
			// 文件操作
			"ls", "cat", "head", "tail", "less", "more",
			"grep", "find", "wc", "sort", "uniq",

			// 目錄操作
			"pwd", "cd", "mkdir", "tree",

			// 系統信息
			"date", "whoami", "hostname", "uname",
			"df", "du", "free", "top", "ps",

			// 網絡（只讀）
			"ping", "traceroute", "nslookup", "dig",

			// Git
			"git status", "git log", "git diff", "git branch",

			// 其他
			"echo", "printf", "which", "whereis",
		},
	}
}

// ValidateCommand 驗證命令是否安全
// cmd: 命令名稱
// args: 命令參數
func (v *CommandValidator) ValidateCommand(cmd string, args []string) error {
	// 構建完整命令
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd = cmd + " " + strings.Join(args, " ")
	}

	// 如果有白名單，只檢查白名單
	if len(v.whitelist) > 0 {
		return v.checkWhitelist(cmd, fullCmd)
	}

	// 否則檢查黑名單
	return v.checkBlacklist(fullCmd)
}

// checkWhitelist 檢查命令是否在白名單中
func (v *CommandValidator) checkWhitelist(cmd string, fullCmd string) error {
	// 檢查命令是否在白名單中
	for _, allowed := range v.whitelist {
		if cmd == allowed || strings.HasPrefix(fullCmd, allowed) {
			return nil
		}
	}

	return fmt.Errorf("命令 '%s' 不在白名單中", cmd)
}

// checkBlacklist 檢查命令是否包含危險模式
func (v *CommandValidator) checkBlacklist(fullCmd string) error {
	// 檢查黑名單
	for _, pattern := range v.blacklist {
		if strings.Contains(fullCmd, pattern) {
			return fmt.Errorf("命令包含危險模式: '%s'", pattern)
		}
	}

	// 檢查危險字符（可能的命令注入）
	dangerousChars := map[string]string{
		";":  "命令分隔符",
		"|":  "管道符",
		"&":  "後台執行符",
		"`":  "命令替換",
		"$":  "變量替換",
		"(":  "子shell",
		")":  "子shell",
		"<":  "輸入重定向",
		">":  "輸出重定向",
		"\\": "轉義字符",
		"\n": "換行符",
	}

	for char, desc := range dangerousChars {
		if strings.Contains(fullCmd, char) {
			return fmt.Errorf("命令包含危險字符 '%s' (%s)", char, desc)
		}
	}

	// 特別檢查 curl 和 wget（常被用於下載惡意腳本）
	lowerCmd := strings.ToLower(fullCmd)
	if strings.Contains(lowerCmd, "curl") || strings.Contains(lowerCmd, "wget") {
		// 檢查是否有管道或腳本執行
		if strings.Contains(lowerCmd, "bash") ||
			strings.Contains(lowerCmd, "sh") ||
			strings.Contains(lowerCmd, "python") ||
			strings.Contains(lowerCmd, "perl") {
			return fmt.Errorf("禁止使用 curl/wget 直接執行腳本")
		}
	}

	return nil
}

// IsCommandSafe 快速檢查命令字符串是否明顯不安全
// 這是一個輕量級的檢查，不應該作為唯一的驗證
func IsCommandSafe(cmd string) bool {
	// 檢查是否包含明顯的危險模式
	dangerousPatterns := []string{
		"rm -rf",
		"mkfs",
		"format",
		"dd if=",
		"> /dev/",
		"sudo",
		"su -",
		"shutdown",
		"reboot",
	}

	lowerCmd := strings.ToLower(cmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerCmd, pattern) {
			return false
		}
	}

	return true
}

// SanitizeCommandArgs 清理命令參數，移除潛在的危險字符
// 注意：這不能替代完整的驗證，只是額外的防護層
func SanitizeCommandArgs(args []string) []string {
	sanitized := make([]string, 0, len(args))

	for _, arg := range args {
		// 移除前後的空白
		arg = strings.TrimSpace(arg)

		// 跳過空參數
		if arg == "" {
			continue
		}

		// 檢查是否包含危險字符
		if strings.ContainsAny(arg, ";|&`$()<>\\") {
			// 如果包含危險字符，用引號包圍
			// 但這仍然不夠安全，應該由 ValidateCommand 攔截
			arg = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}

		sanitized = append(sanitized, arg)
	}

	return sanitized
}
