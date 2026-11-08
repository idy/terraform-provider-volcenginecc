// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// certificateOnlyHTTPSChange admits only a change to an existing, enabled,
// single ordinary certificate binding. A changed cert_id or source must be
// explicitly configured; cert_id may be unknown until a certificate is renewed.
// A source must resolve to one of the two supported hosting locations.
//
// cert_name, effective_time and expire_time are treated as response metadata
// only when unconfigured. Explicitly configuring any of them excludes a binding
// change from this narrow update path, even when their values have not changed:
// the binding API cannot promise to preserve metadata belonging to the old cert.
// encry_type may be omitted (the ordinary certificate default) or inter_cert.
// The apply implementation must validate the resolved certificate independently.
func certificateOnlyHTTPSChange(state, plan, config types.Object) bool {
	if !certificateHTTPSKnownObjects(state, plan, config) {
		return false
	}

	s, p, c := state.Attributes(), plan.Attributes(), config.Attributes()
	stateSwitch, ok := s["switch"].(types.Bool)
	if !ok || stateSwitch.IsNull() || stateSwitch.IsUnknown() || !stateSwitch.ValueBool() {
		return false
	}
	planSwitch, ok := certificateHTTPSPlannedValue(s["switch"], p["switch"], c["switch"]).(types.Bool)
	if !ok || planSwitch.IsNull() || planSwitch.IsUnknown() || !planSwitch.ValueBool() {
		return false
	}

	stateCert, sok := s["cert_info"].(types.Object)
	planCert, pok := p["cert_info"].(types.Object)
	configCert, cok := c["cert_info"].(types.Object)
	if !sok || !pok || !cok || !certificateHTTPSKnownObjects(stateCert, planCert, configCert) {
		return false
	}

	// An absent/empty dual-cert list is harmless. An unknown unconfigured
	// computed list inherits its prior absence; an explicitly unknown list is
	// not evidence that this remains a single-certificate binding.
	if !certificateHTTPSEmptyCertList(s["cert_info_list"]) ||
		!certificateHTTPSEmptyCertList(c["cert_info_list"]) ||
		!certificateHTTPSEmptyCertList(certificateHTTPSPlannedValue(s["cert_info_list"], p["cert_info_list"], c["cert_info_list"])) {
		return false
	}

	for name, before := range s {
		if name != "cert_info" && name != "cert_info_list" && !certificateHTTPSValueUnchanged(before, p[name], c[name]) {
			return false
		}
	}

	s, p, c = stateCert.Attributes(), planCert.Attributes(), configCert.Attributes()
	for _, name := range []string{"cert_name", "effective_time", "expire_time"} {
		if c[name] == nil || !c[name].IsNull() {
			return false
		}
	}
	if !certificateHTTPSNoMaterial(s["certificate"]) || !certificateHTTPSNoMaterial(c["certificate"]) ||
		!certificateHTTPSNoMaterial(certificateHTTPSPlannedValue(s["certificate"], p["certificate"], c["certificate"])) {
		return false
	}
	if !certificateHTTPSOrdinaryEncryption(s["encry_type"]) || !certificateHTTPSOrdinaryEncryption(c["encry_type"]) ||
		!certificateHTTPSOrdinaryEncryption(certificateHTTPSPlannedValue(s["encry_type"], p["encry_type"], c["encry_type"])) {
		return false
	}

	changed := false
	for _, name := range []string{"cert_id", "source"} {
		before, bok := s[name].(types.String)
		after, aok := certificateHTTPSPlannedValue(s[name], p[name], c[name]).(types.String)
		configured, cok := c[name].(types.String)
		if !bok || !aok || !cok || before.IsNull() || before.IsUnknown() || before.ValueString() == "" || after.IsNull() {
			return false
		}
		if name == "source" {
			if !certificateHTTPSKnownSource(before) || !certificateHTTPSKnownSource(after) || configured.IsUnknown() {
				return false
			}
		} else if !after.IsUnknown() && after.ValueString() == "" {
			return false
		}
		if !configured.IsNull() && !configured.IsUnknown() && !configured.Equal(after) {
			return false
		}
		if !before.Equal(after) {
			if configured.IsNull() {
				return false
			}
			changed = true
		}
	}

	// Preserve the replacement boundary if upstream adds another CertInfo field.
	for name, before := range s {
		switch name {
		case "cert_id", "source", "cert_name", "effective_time", "expire_time", "encry_type", "certificate":
			continue
		default:
			if !certificateHTTPSValueUnchanged(before, p[name], c[name]) {
				return false
			}
		}
	}
	return changed
}

// certificateHTTPSRequiresReplace replaces the generated HTTPS object's
// RequiresReplaceIfConfigured, retaining its resource-create/delete and
// unconfigured-attribute behavior. It changes no plan values and does not clear
// replacement requested by any other attribute.
func certificateHTTPSRequiresReplace() planmodifier.Object {
	const description = "Changes to configured HTTPS settings require replacement, except an explicitly configured single ordinary certificate binding change."
	return objectplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.ObjectRequest, resp *objectplanmodifier.RequiresReplaceIfFuncResponse) {
			if req.ConfigValue.IsNull() || certificateOnlyHTTPSChange(req.StateValue, req.PlanValue, req.ConfigValue) ||
				certificateHTTPSUnchanged(req.StateValue, req.PlanValue, req.ConfigValue) {
				return
			}
			resp.RequiresReplace = true
		},
		description, description,
	)
}

// certificateHTTPSUnchanged also recognizes unconfigured computed metadata as
// a no-op. In particular, metadata becoming unknown without a binding change
// must not manufacture a CDN replacement.
func certificateHTTPSUnchanged(state, plan, config types.Object) bool {
	if !certificateHTTPSKnownObjects(state, plan, config) {
		return false
	}
	s, p, c := state.Attributes(), plan.Attributes(), config.Attributes()
	for name, before := range s {
		if name == "cert_info" {
			stateCert, sok := before.(types.Object)
			planCert, pok := p[name].(types.Object)
			configCert, cok := c[name].(types.Object)
			if sok && pok && cok && !stateCert.IsNull() && !stateCert.IsUnknown() && !planCert.IsNull() && !planCert.IsUnknown() && !configCert.IsUnknown() {
				sa, pa, ca := stateCert.Attributes(), planCert.Attributes(), configCert.Attributes()
				for field, value := range sa {
					switch field {
					case "cert_name", "effective_time", "expire_time":
						if ca[field] == nil || ca[field].IsNull() {
							continue
						}
					}
					if !certificateHTTPSValueUnchanged(value, pa[field], ca[field]) {
						return false
					}
				}
				continue
			}
		}
		if !certificateHTTPSValueUnchanged(before, p[name], c[name]) {
			return false
		}
	}
	return true
}

func certificateHTTPSKnownObjects(state, plan, config types.Object) bool {
	return !state.IsNull() && !state.IsUnknown() && !plan.IsNull() && !plan.IsUnknown() && !config.IsNull() && !config.IsUnknown() &&
		state.Type(context.Background()).Equal(plan.Type(context.Background())) &&
		state.Type(context.Background()).Equal(config.Type(context.Background()))
}

// HTTPS children are Optional+Computed. Their generated state-preservation
// modifiers run after the parent object's replacement modifier. Omitted
// computed unknowns therefore do not establish a configured change, including
// previously null children which UseNonNullStateForUnknown leaves unknown.
func certificateHTTPSPlannedValue(state, plan, config attr.Value) attr.Value {
	if plan != nil && plan.IsUnknown() && (config == nil || config.IsNull()) {
		return state
	}
	return plan
}

func certificateHTTPSValueUnchanged(state, plan, config attr.Value) bool {
	return certificateOriginConfiguredUnchanged(context.Background(), state, plan, config)
}

func certificateHTTPSEmptyCertList(value attr.Value) bool {
	if value == nil || value.IsUnknown() {
		return false
	}
	list, ok := value.(types.Set)
	return ok && (list.IsNull() || len(list.Elements()) == 0)
}

func certificateHTTPSNoMaterial(value attr.Value) bool {
	if value == nil || value.IsUnknown() {
		return false
	}
	material, ok := value.(types.Object)
	if !ok || material.IsNull() {
		return ok
	}
	for _, value := range material.Attributes() {
		text, ok := value.(types.String)
		if !ok || text.IsUnknown() || (!text.IsNull() && text.ValueString() != "") {
			return false
		}
	}
	return true
}

func certificateHTTPSOrdinaryEncryption(value attr.Value) bool {
	text, ok := value.(types.String)
	return ok && !text.IsUnknown() && (text.IsNull() || text.ValueString() == "" || text.ValueString() == "inter_cert")
}

func certificateHTTPSKnownSource(value types.String) bool {
	return !value.IsNull() && !value.IsUnknown() && (value.ValueString() == "volc_cert_center" || value.ValueString() == "cdn_cert_hosting")
}

// certificateOriginPreserveUnconfigured runs before origin's generated
// RequiresReplace. A certificate change can turn omitted computed origin
// children from null to unknown, changing the enclosing set's identity before
// the children run UseNonNullStateForUnknown (which cannot preserve null).
//
// Preserve the prior origin only when every configured value is known and
// matches prior state, and the remaining planned differences consist entirely
// of unknown, unconfigured values. Sets are associated by unique configuration
// projections, never by position; ambiguous or oversized comparisons fall back
// to the generated replacement rule.
func certificateOriginPreserveUnconfigured() planmodifier.Set {
	return certificateOriginPreserveUnconfiguredModifier{}
}

type certificateOriginPreserveUnconfiguredModifier struct{}

func (certificateOriginPreserveUnconfiguredModifier) Description(context.Context) string {
	return "Preserve unchanged origins, including null computed values, when configured set elements uniquely match prior state and all configured values are known."
}

func (modifier certificateOriginPreserveUnconfiguredModifier) MarkdownDescription(ctx context.Context) string {
	return modifier.Description(ctx)
}

func (certificateOriginPreserveUnconfiguredModifier) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || req.StateValue.IsNull() || req.StateValue.IsUnknown() ||
		req.PlanValue.IsNull() || req.PlanValue.IsUnknown() || req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	prior, err := req.StateValue.ToTerraformValue(ctx)
	if err != nil || !prior.IsFullyKnown() {
		return
	}
	if certificateOriginConfiguredUnchanged(ctx, req.StateValue, req.PlanValue, req.ConfigValue) {
		resp.PlanValue = req.StateValue
	}
}

// A nil config represents an omitted value while descending objects or sets.
// Configured objects/sets are always traversed, even if state and plan compare equal, so an
// explicitly unknown descendant can never be mistaken for omitted metadata.
func certificateOriginConfiguredUnchanged(ctx context.Context, state, plan, config attr.Value) bool {
	comparison := certificatePlanComparison{ctx: ctx, remaining: 100000}
	return comparison.unchanged(state, plan, config)
}

// Bound both individual sets and the total recursive work. Unsupported large
// shapes conservatively retain upstream replacement behavior. The 64-element
// bound includes the CDN API's maximum of 50 origin addresses.
const certificatePlanMaxSet = 64

type certificatePlanComparison struct {
	ctx       context.Context
	remaining int
}

func (comparison *certificatePlanComparison) unchanged(state, plan, config attr.Value) bool {
	comparison.remaining--
	ctx := comparison.ctx
	if comparison.remaining < 0 || state == nil || plan == nil || state.IsUnknown() || (config != nil && config.IsUnknown()) ||
		!state.Type(ctx).Equal(plan.Type(ctx)) || (config != nil && !state.Type(ctx).Equal(config.Type(ctx))) {
		return false
	}
	omitted := config == nil || config.IsNull()
	if omitted && (plan.IsUnknown() || state.Equal(plan)) {
		return true
	}
	if state.IsNull() || plan.IsNull() || plan.IsUnknown() {
		return false
	}
	switch before := state.(type) {
	case types.Object:
		after, ok := plan.(types.Object)
		if !ok {
			return false
		}
		var configured map[string]attr.Value
		if !omitted {
			object, ok := config.(types.Object)
			if !ok {
				return false
			}
			configured = object.Attributes()
		}
		previous, proposed := before.Attributes(), after.Attributes()
		if len(previous) != len(proposed) {
			return false
		}
		for name, value := range previous {
			if !comparison.unchanged(value, proposed[name], configured[name]) {
				return false
			}
		}
		return true
	case types.Set:
		after, ok := plan.(types.Set)
		if !ok {
			return false
		}
		previous, proposed := before.Elements(), after.Elements()
		if len(previous) != len(proposed) || len(previous) > certificatePlanMaxSet {
			return false
		}
		if omitted {
			_, unique := comparison.uniqueMatch(len(previous), func(left, right int) bool {
				return comparison.unchanged(previous[left], proposed[right], nil)
			})
			return unique
		}
		set, ok := config.(types.Set)
		if !ok || len(set.Elements()) != len(previous) {
			return false
		}
		configured := set.Elements()
		// First identify each configured element uniquely in prior state using
		// only its explicit projection. Then associate that same configuration
		// with a unique planned element, checking every known planned field.
		priorMatch, unique := comparison.uniqueMatch(len(previous), func(left, right int) bool {
			return comparison.unchanged(previous[right], previous[right], configured[left])
		})
		if !unique {
			return false
		}
		_, unique = comparison.uniqueMatch(len(proposed), func(left, right int) bool {
			return comparison.unchanged(previous[priorMatch[left]], proposed[right], configured[left])
		})
		return unique
	default:
		return !omitted && state.Equal(config) && state.Equal(plan)
	}
}

// Find a perfect bipartite matching, then reject alternating cycles (which
// prove another perfect matching exists). This is polynomial, rather than
// enumerating permutations or trusting Terraform set element positions.
func (comparison *certificatePlanComparison) uniqueMatch(size int, accepts func(int, int) bool) ([]int, bool) {
	if size > certificatePlanMaxSet || comparison.remaining < 0 {
		return nil, false
	}
	edges := make([][]bool, size)
	for left := range edges {
		edges[left] = make([]bool, size)
		for right := range edges[left] {
			edges[left][right] = accepts(left, right)
			if comparison.remaining < 0 {
				return nil, false
			}
		}
	}
	rightToLeft := make([]int, size)
	for right := range rightToLeft {
		rightToLeft[right] = -1
	}
	var augment func(int, []bool) bool
	augment = func(left int, seen []bool) bool {
		for right, edge := range edges[left] {
			if !edge || seen[right] {
				continue
			}
			seen[right] = true
			if rightToLeft[right] == -1 || augment(rightToLeft[right], seen) {
				rightToLeft[right] = left
				return true
			}
		}
		return false
	}
	for left := range edges {
		if !augment(left, make([]bool, size)) {
			return nil, false
		}
	}
	leftToRight := make([]int, size)
	for right, left := range rightToLeft {
		leftToRight[left] = right
	}
	colors := make([]uint8, size)
	var cycle func(int) bool
	cycle = func(left int) bool {
		colors[left] = 1
		for right, edge := range edges[left] {
			if !edge || leftToRight[left] == right {
				continue
			}
			next := rightToLeft[right]
			if colors[next] == 1 || (colors[next] == 0 && cycle(next)) {
				return true
			}
		}
		colors[left] = 2
		return false
	}
	for left := range edges {
		if colors[left] == 0 && cycle(left) {
			return nil, false
		}
	}
	return leftToRight, true
}
