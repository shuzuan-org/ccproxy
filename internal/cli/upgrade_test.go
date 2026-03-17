package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpgradeCmd_Registered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "upgrade" {
			found = true
			break
		}
	}
	assert.True(t, found, "upgrade command should be registered")
}

func TestUpgradeCmd_Flags(t *testing.T) {
	var found *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "upgrade" {
			found = cmd
			break
		}
	}
	require.NotNil(t, found)

	checkFlag := found.Flags().Lookup("check")
	assert.NotNil(t, checkFlag, "--check flag should exist")

	forceFlag := found.Flags().Lookup("force")
	assert.NotNil(t, forceFlag, "--force flag should exist")
}
