package linux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const tableOwner = "netkit-managed-v1"
const chainOwner = "netkit-ingress-v1"

type AppliedRule struct {
	ID     string `json:"id"`
	Handle uint64 `json:"handle"`
	Rule   Rule   `json:"rule"`
}

type nftObject struct {
	Family   string `json:"family"`
	Name     string `json:"name"`
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Comment  string `json:"comment"`
	Handle   uint64 `json:"handle"`
	Hook     string `json:"hook"`
	Type     string `json:"type"`
	Priority int    `json:"prio"`
	Policy   string `json:"policy"`
}

type nftState struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

func managedState(ctx context.Context) ([]nftObject, bool, error) {
	output, err := nftRun(ctx, "", "-j", "-a", "list", "ruleset")
	if err != nil {
		return nil, false, err
	}
	var state nftState
	if err := json.Unmarshal([]byte(output), &state); err != nil {
		return nil, false, fmt.Errorf("decode nft JSON: %w", err)
	}
	var rules []nftObject
	tableFound, chainFound := false, false
	for _, entry := range state.NFTables {
		for kind, raw := range entry {
			if kind != "table" && kind != "chain" && kind != "rule" {
				continue
			}
			var obj nftObject
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, false, err
			}
			if obj.Family != "inet" {
				continue
			}
			switch kind {
			case "table":
				if obj.Name == "netkit" {
					if obj.Comment != tableOwner {
						return nil, false, errors.New("inet netkit table is not owned by netkit")
					}
					tableFound = true
				}
			case "chain":
				if obj.Table == "netkit" && obj.Name == "ingress" {
					if obj.Comment != chainOwner || obj.Hook != "input" || obj.Type != "filter" || obj.Priority != 0 || obj.Policy != "accept" {
						return nil, false, errors.New("netkit ingress chain ownership or configuration changed")
					}
					chainFound = true
				}
			case "rule":
				if obj.Table == "netkit" && obj.Chain == "ingress" {
					rules = append(rules, obj)
				}
			}
		}
	}
	if tableFound != chainFound {
		return nil, false, errors.New("netkit table/chain state is incomplete; refusing mutation")
	}
	return rules, tableFound, nil
}

// ManagedApply appends one owned ingress rule atomically. It never flushes rules
// or changes policies. Removal uses the returned ID, not display order. This is
// local namespace mutation; no rollback timer or persisted transaction is offered.
func ManagedApply(ctx context.Context, rule Rule) (AppliedRule, error) {
	plan, err := FirewallPlan(rule)
	if err != nil {
		return AppliedRule{}, err
	}
	_, exists, err := managedState(ctx)
	if err != nil {
		return AppliedRule{}, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return AppliedRule{}, err
	}
	id := "netkit-v1-" + hex.EncodeToString(random)
	var commands []string
	if !exists {
		commands = append(commands, plan.Commands[:2]...)
	}
	commands = append(commands, plan.Commands[2]+` comment "`+id+`"`)
	// Keep recovery information before dispatch: cancellation or backend failure
	// can occur after the kernel has committed the atomic batch.
	applied := AppliedRule{ID: id, Rule: plan.Rule}
	if _, err := nftRun(ctx, strings.Join(commands, "\n")+"\n", "-f", "-"); err != nil {
		return applied, fmt.Errorf("rule may have committed; inspect managed ID %s before retrying: %w", id, err)
	}
	rules, _, err := managedState(ctx)
	if err != nil {
		return applied, fmt.Errorf("rule committed but handle lookup failed: %w", err)
	}
	for _, obj := range rules {
		if obj.Comment == id {
			applied.Handle = obj.Handle
			return applied, nil
		}
	}
	return applied, errors.New("rule committed but was changed before handle lookup")
}

// ManagedRemove resolves an owned comment to its current kernel handle and
// deletes only that rule. External concurrent edits are not a persisted CAS
// transaction; coordinate other firewall managers when mutating this table.
func ManagedRemove(ctx context.Context, id string) error {
	if !strings.HasPrefix(id, "netkit-v1-") || len(id) != 42 {
		return errors.New("invalid managed rule ID")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, "netkit-v1-")); err != nil {
		return errors.New("invalid managed rule ID")
	}
	rules, _, err := managedState(ctx)
	if err != nil {
		return err
	}
	var handle uint64
	count := 0
	for _, obj := range rules {
		if obj.Comment == id {
			handle = obj.Handle
			count++
		}
	}
	if count != 1 || handle == 0 {
		return errors.New("managed rule is missing or its ownership ID is ambiguous")
	}
	_, err = nftRun(ctx, fmt.Sprintf("delete rule inet netkit ingress handle %d\n", handle), "-f", "-")
	return err
}
