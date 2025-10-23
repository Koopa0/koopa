package cmd

import (
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "koopa",
	Short: i18n.T("app.description"),
	Long:  i18n.T("root.description"),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to chat mode when no arguments
		return runChat(cmd, args)
	},
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add global --lang flag
	rootCmd.PersistentFlags().StringP("lang", "l", "", i18n.T("root.lang.flag"))

	// Handle language flag before command execution
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if lang, _ := cmd.Flags().GetString("lang"); lang != "" {
			i18n.SetLanguage(lang)
		}
		return nil
	}
}
