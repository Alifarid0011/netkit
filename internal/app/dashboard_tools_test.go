package app

import (
	"strings"
	"testing"
)

func TestDashboardToolsBuildSafeCommands(t *testing.T) {
	for _, tool := range dashboardTools() {
		values := make([]string, len(tool.Fields))
		for i, f := range tool.Fields {
			values[i] = f.Default
		}
		if tool.ID == "firewall-remove" {
			values[0] = "netkit-v1-01234567890123456789012345678901"
		}
		if tool.ID == "router-remove" {
			values[len(values)-1] = "*A"
		}
		if tool.ID == "pcap" {
			values[0] = "sample.pcap"
		}
		args, err := tool.arguments(values)
		if err != nil {
			t.Errorf("%s %v", tool.ID, err)
			continue
		}
		if len(args) == 0 || args[0] == "tui" {
			t.Fatalf("invalid action %s", tool.ID)
		}
		for _, arg := range args {
			if arg == "sh" || arg == "bash" {
				t.Fatalf("shell action %s", tool.ID)
			}
		}
	}
}
func TestDashboardSecretsNeverEnterArguments(t *testing.T) {
	for _, tool := range dashboardTools() {
		if !strings.HasPrefix(tool.ID, "router-") {
			continue
		}
		values := make([]string, len(tool.Fields))
		for i, field := range tool.Fields {
			values[i] = field.Default
			if field.Secret {
				values[i] = "do-not-render-this"
			}
		}
		if tool.ID == "router-remove" {
			values[len(values)-1] = "*A"
		}
		args, err := tool.arguments(values)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(args, " "), "do-not-render-this") {
			t.Fatal("password leaked to argv")
		}
	}
}
func TestDashboardMutationsAreExplicit(t *testing.T) {
	for _, tool := range dashboardTools() {
		if tool.ID == "firewall-apply" || tool.ID == "firewall-remove" || tool.ID == "router-add" || tool.ID == "router-remove" {
			if !tool.Mutation {
				t.Fatal("unconfirmed mutation", tool.ID)
			}
		}
	}
}
func TestDashboardMissingInput(t *testing.T) {
	for _, tool := range dashboardTools() {
		if tool.ID == "doctor" {
			if _, err := tool.arguments([]string{""}); err == nil {
				t.Fatal("accepted empty destination")
			}
		}
	}
}
