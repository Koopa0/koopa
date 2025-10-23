package security

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// HTTPValidator HTTP 請求驗證器
// 用於防止 SSRF (Server-Side Request Forgery) 攻擊
type HTTPValidator struct {
	maxResponseSize int64
	allowedSchemes  []string
}

// NewHTTPValidator 創建 HTTP 驗證器
func NewHTTPValidator() *HTTPValidator {
	return &HTTPValidator{
		maxResponseSize: 5 * 1024 * 1024, // 5MB
		allowedSchemes:  []string{"http", "https"},
	}
}

// ValidateURL 驗證 URL 是否安全
// 檢查協議、主機、IP 地址範圍等
func (v *HTTPValidator) ValidateURL(urlStr string) error {
	// 1. 解析 URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("無效的 URL: %w", err)
	}

	// 2. 檢查協議
	lowercasedScheme := strings.ToLower(parsedURL.Scheme)
	if !slices.Contains(v.allowedSchemes, lowercasedScheme) {
		return fmt.Errorf("不允許的協議: %s（僅允許 http/https）", parsedURL.Scheme)
	}

	// 3. 獲取主機名
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("無效的主機名")
	}

	// 4. 檢查是否為危險的主機名
	if isDangerousHostname(hostname) {
		return fmt.Errorf("拒絕訪問: 不允許訪問內部網絡或元數據服務")
	}

	// 5. 解析主機名為 IP 地址
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("無法解析主機名: %w", err)
	}

	// 6. 檢查所有解析出的 IP 地址
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("拒絕訪問: 不允許訪問內部網絡 IP (%s)", ip.String())
		}
	}

	return nil
}

// GetMaxResponseSize 獲取最大回應大小限制
func (v *HTTPValidator) GetMaxResponseSize() int64 {
	return v.maxResponseSize
}

// CreateSafeHTTPClient 創建帶有安全配置的 HTTP 客戶端
func (v *HTTPValidator) CreateSafeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 限制最多 3 次重定向
			if len(via) >= 3 {
				return fmt.Errorf("停止在 3 次重定向後")
			}

			// 檢查重定向的 URL 是否安全
			if err := v.ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("重定向到不安全的 URL: %w", err)
			}

			return nil
		},
	}
}

// isDangerousHostname 檢查是否為危險的主機名
func isDangerousHostname(hostname string) bool {
	hostname = strings.ToLower(hostname)

	// 本地主機名稱
	localHostnames := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
	}

	if slices.Contains(localHostnames, hostname) {
		return true
	}

	// 雲服務元數據端點
	metadataEndpoints := []string{
		"169.254.169.254", // AWS, Azure, GCP
		"metadata.google.internal",
		"metadata",
	}

	for _, endpoint := range metadataEndpoints {
		if hostname == endpoint || strings.Contains(hostname, endpoint) {
			return true
		}
	}

	return false
}

// isPrivateIP 檢查 IP 是否為私有 IP 地址
func isPrivateIP(ip net.IP) bool {
	// IPv4 私有網段
	privateIPv4Ranges := []string{
		"10.0.0.0/8",     // Class A 私有網段
		"172.16.0.0/12",  // Class B 私有網段
		"192.168.0.0/16", // Class C 私有網段
		"127.0.0.0/8",    // 本地回環
		"169.254.0.0/16", // 鏈路本地地址（AWS 元數據等）
		"0.0.0.0/8",      // 本地網絡
		"224.0.0.0/4",    // 組播地址
		"240.0.0.0/4",    // 保留地址
	}

	for _, cidr := range privateIPv4Ranges {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}

	// IPv6 私有地址檢查
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// IPv6 本地唯一地址 (ULA) fc00::/7
	if len(ip) == net.IPv6len && ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// IsURLSafe 快速檢查 URL 是否包含明顯的危險模式
// 這是一個額外的保護層，但不應該單獨依賴
func IsURLSafe(urlStr string) bool {
	urlLower := strings.ToLower(urlStr)

	// 檢查危險的協議
	dangerousSchemes := []string{
		"file://",
		"ftp://",
		"gopher://",
		"data:",
		"javascript:",
	}

	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(urlLower, scheme) {
			return false
		}
	}

	// 檢查是否包含內部 IP 模式
	dangerousPatterns := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"169.254.169.254",
		"metadata",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(urlLower, pattern) {
			return false
		}
	}

	return true
}
