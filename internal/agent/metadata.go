package agent

// DangerLevel indicates the risk level of a tool operation.
type DangerLevel int

const (
	DangerLevelSafe DangerLevel = iota
	DangerLevelWarning
	DangerLevelDangerous
	DangerLevelCritical
)

// ToolMetadata defines business properties for tools.
type ToolMetadata struct {
	RequiresConfirmation bool
	DangerLevel          DangerLevel
	IsDangerousFunc      func(params map[string]any) bool
}
