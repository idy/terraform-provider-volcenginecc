// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// Delegated modules can retain bootstrap configuration after ignore_changes has
// selected their actual prior values for the plan. Compare only known planned
// values with prior state, but reject any explicitly unknown configuration.
// Restore whole modules before their generated replacement modifiers run so
// computed nulls becoming unknown do not manufacture replacement differences.
func delegatedModulePlanUnchanged(ctx context.Context, state, plan, config attr.Value) bool {
	prior, err := state.ToTerraformValue(ctx)
	if err != nil || !prior.IsFullyKnown() {
		return false
	}
	configured, err := config.ToTerraformValue(ctx)
	if err != nil || !configured.IsFullyKnown() {
		return false
	}
	// A nil configuration uses the known-plan projection and unique unordered
	// set matching, including its conservative comparison complexity bounds.
	return certificateOriginConfiguredUnchanged(ctx, state, plan, nil)
}

func delegatedModulePreserveSet() planmodifier.Set {
	return delegatedModulePreserveSetModifier{}
}

type delegatedModulePreserveSetModifier struct{}

func (delegatedModulePreserveSetModifier) Description(context.Context) string {
	return "Preserve prior delegated module values when all configuration is known and the plan differs only in unknown values with unique set matching."
}

func (modifier delegatedModulePreserveSetModifier) MarkdownDescription(ctx context.Context) string {
	return modifier.Description(ctx)
}

func (delegatedModulePreserveSetModifier) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	if delegatedModulePlanUnchanged(ctx, req.StateValue, req.PlanValue, req.ConfigValue) {
		resp.PlanValue = req.StateValue
	}
}

func delegatedModulePreserveObject() planmodifier.Object {
	return delegatedModulePreserveObjectModifier{}
}

type delegatedModulePreserveObjectModifier struct{}

func (delegatedModulePreserveObjectModifier) Description(ctx context.Context) string {
	return delegatedModulePreserveSetModifier{}.Description(ctx)
}

func (modifier delegatedModulePreserveObjectModifier) MarkdownDescription(ctx context.Context) string {
	return modifier.Description(ctx)
}

func (delegatedModulePreserveObjectModifier) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	if delegatedModulePlanUnchanged(ctx, req.StateValue, req.PlanValue, req.ConfigValue) {
		resp.PlanValue = req.StateValue
	}
}
