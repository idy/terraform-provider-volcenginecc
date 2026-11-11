// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func delegatedSchemas(t *testing.T) (schema.Schema, schema.Schema) {
	t.Helper()
	ctx := context.Background()
	inner, err := domainResource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original := &resource.SchemaResponse{}
	inner.Schema(ctx, resource.SchemaRequest{}, original)
	wrapped := &resource.SchemaResponse{}
	(&domainHTTPSResource{Resource: &domainHTTPSInnerFake{schema: original.Schema}}).Schema(ctx, resource.SchemaRequest{}, wrapped)
	if original.Diagnostics.HasError() || wrapped.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: original=%v wrapped=%v", original.Diagnostics, wrapped.Diagnostics)
	}
	return original.Schema, wrapped.Schema
}

func TestDelegatedModuleSchema(t *testing.T) {
	t.Parallel()
	original, wrapped := delegatedSchemas(t)
	for name, prior := range original.Attributes {
		switch name {
		case "cache", "browser_cache", "response_header":
			before := prior.(schema.SetNestedAttribute)
			after := wrapped.Attributes[name].(schema.SetNestedAttribute)
			if len(after.PlanModifiers) != len(before.PlanModifiers)+1 {
				t.Fatalf("%s modifiers = %d, want %d", name, len(after.PlanModifiers), len(before.PlanModifiers)+1)
			}
			if _, ok := after.PlanModifiers[0].(delegatedModulePreserveSetModifier); !ok {
				t.Errorf("%s first modifier = %T", name, after.PlanModifiers[0])
			}
			for i, modifier := range before.PlanModifiers {
				actual := after.PlanModifiers[i+1]
				// Replacement modifiers contain function closures, which are
				// never reflect.DeepEqual even when copied without changes.
				ctx := context.Background()
				if reflect.TypeOf(modifier) != reflect.TypeOf(actual) || modifier.Description(ctx) != actual.Description(ctx) || modifier.MarkdownDescription(ctx) != actual.MarkdownDescription(ctx) {
					t.Errorf("%s changed original modifier %d", name, i)
				}
			}
			after.PlanModifiers = before.PlanModifiers
			if !reflect.DeepEqual(before, after) {
				t.Errorf("%s changed beyond prepended modifier", name)
			}
		case "origin_rewrite":
			before := prior.(schema.SingleNestedAttribute)
			after := wrapped.Attributes[name].(schema.SingleNestedAttribute)
			if len(after.PlanModifiers) != len(before.PlanModifiers)+1 {
				t.Fatalf("%s modifiers = %d, want %d", name, len(after.PlanModifiers), len(before.PlanModifiers)+1)
			}
			if _, ok := after.PlanModifiers[0].(delegatedModulePreserveObjectModifier); !ok {
				t.Errorf("%s first modifier = %T", name, after.PlanModifiers[0])
			}
			for i, modifier := range before.PlanModifiers {
				actual := after.PlanModifiers[i+1]
				// Replacement modifiers contain function closures, which are
				// never reflect.DeepEqual even when copied without changes.
				ctx := context.Background()
				if reflect.TypeOf(modifier) != reflect.TypeOf(actual) || modifier.Description(ctx) != actual.Description(ctx) || modifier.MarkdownDescription(ctx) != actual.MarkdownDescription(ctx) {
					t.Errorf("%s changed original modifier %d", name, i)
				}
			}
			after.PlanModifiers = before.PlanModifiers
			if !reflect.DeepEqual(before, after) {
				t.Errorf("%s changed beyond prepended modifier", name)
			}
		case "https", "origin": // These already have separate wrapper behavior.
		default:
			if !reflect.DeepEqual(prior, wrapped.Attributes[name]) {
				t.Errorf("unexpected schema change to %s", name)
			}
		}
	}
	for _, name := range []string{"cache", "browser_cache", "response_header", "origin_rewrite"} {
		for _, missing := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/wrong-type", true: "/missing"}[missing], func(t *testing.T) {
				attributes := make(map[string]schema.Attribute, len(original.Attributes))
				for key, value := range original.Attributes {
					attributes[key] = value
				}
				if missing {
					delete(attributes, name)
				} else {
					attributes[name] = schema.StringAttribute{Optional: true}
				}
				inner := &domainHTTPSInnerFake{schema: schema.Schema{Attributes: attributes}}
				resp := &resource.SchemaResponse{}
				(&domainHTTPSResource{Resource: inner}).Schema(context.Background(), resource.SchemaRequest{}, resp)
				if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), name) {
					t.Fatalf("want module-specific diagnostic for %s, got %v", name, resp.Diagnostics)
				}
			})
		}
	}
}

func TestDelegatedModulePlan(t *testing.T) {
	t.Parallel()
	original, wrapped := delegatedSchemas(t)
	ctx := context.Background()
	for _, name := range []string{"cache", "browser_cache", "response_header", "origin_rewrite"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newDelegatedModuleFixture(t, name, wrapped.Attributes[name])
			state := fixture.module(fixture.prior...)
			plan := fixture.module(fixture.planned[1], fixture.planned[0])
			unknown := func(typ attr.Type) attr.Value {
				value, err := typ.ValueFromTerraform(ctx, tftypes.NewValue(typ.TerraformType(ctx), tftypes.UnknownValue))
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			null, err := fixture.attribute.GetType().ValueFromTerraform(ctx, tftypes.NewValue(fixture.attribute.GetType().TerraformType(ctx), nil))
			if err != nil {
				t.Fatal(err)
			}
			edit := func(value attr.Value, replacement attr.Value, path ...string) attr.Value {
				return certificateOriginTestSet(t, value, replacement, path...)
			}
			conditionType := fixture.elementType.AttrTypes["condition"].(types.ObjectType)
			ambiguousState := fixture.module(
				edit(fixture.prior[0], types.StringValue("OR"), "condition", "connective"),
				edit(fixture.prior[0], types.StringValue("AND"), "condition", "connective"),
			)
			ambiguousPlan := fixture.module(
				fixture.planned[0],
				edit(fixture.planned[0], certificateHTTPSSet(t, certificateHTTPSObject(t, conditionType), types.StringUnknown(), "connective"), "condition"),
			)
			cases := []struct {
				name                string
				state, plan, config attr.Value
				preserve            bool
				create, destroy     bool
				unconfigured        bool
			}{
				{name: "ignored-bootstrap-values-and-set-length-reordered-null-to-unknown", preserve: true},
				{name: "null-config-allowed", config: null, preserve: true, unconfigured: true},
				{name: "explicit-unknown-config-root", config: unknown(fixture.attribute.GetType())},
				{name: "explicit-unknown-config-object", config: fixture.module(edit(fixture.configElement, types.ObjectUnknown(conditionType.AttrTypes), "condition"))},
				{name: "explicit-unknown-config-leaf-with-known-plan-field", config: fixture.module(edit(fixture.configElement, unknown(fixture.changed.Type(ctx)), fixture.changePath...))},
				{name: "explicit-unknown-config-nested-set", config: fixture.module(edit(fixture.configElement, types.SetUnknown(conditionType.AttrTypes["condition_rule"].(types.SetType).ElemType), "condition", "condition_rule"))},
				{name: "unknown-prior", state: fixture.module(edit(fixture.prior[0], types.ObjectUnknown(conditionType.AttrTypes), "condition"), fixture.prior[1])},
				{name: "known-plan-field-really-changed", plan: fixture.module(edit(fixture.planned[0], fixture.changed, fixture.changePath...), fixture.planned[1])},
				{name: "set-element-added", plan: fixture.module(fixture.planned[0], fixture.planned[1], edit(fixture.planned[0], fixture.changed, fixture.changePath...))},
				{name: "set-element-removed", plan: fixture.module(fixture.planned[0])},
				{name: "ambiguous-known-plan-projection", state: ambiguousState, plan: ambiguousPlan},
				{name: "create-root-even-with-nonnull-attribute", create: true},
				{name: "delete-root-even-with-nonnull-attribute", destroy: true},
				{name: "module-added", state: null},
				{name: "module-removed", plan: null},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					s, p, c := state, plan, fixture.module(fixture.configElement)
					if tc.state != nil {
						s = tc.state
					}
					if tc.plan != nil {
						p = tc.plan
					}
					if tc.config != nil {
						c = tc.config
					}
					if name == "origin_rewrite" && tc.config == nil {
						// The ignored bootstrap switch also differs from actual state.
						c = certificateHTTPSSet(t, c.(types.Object), types.BoolValue(false), "switch")
					}
					want := p
					if tc.preserve {
						want = s
					}
					// Use only the first modifier to prove rejected cases preserve
					// the exact incoming plan, independently of upstream behavior.
					got, replace := delegatedRunModifiers(t, name, fixture.attribute, s, p, c, tc.create, tc.destroy, true)
					if !got.Equal(want) || replace {
						t.Fatalf("preservation = %v, want %v; replacement=%v", got, want, replace)
					}
					got, replace = delegatedRunModifiers(t, name, fixture.attribute, s, p, c, tc.create, tc.destroy, false)
					wantReplace := !tc.preserve && !tc.create && !tc.destroy && !tc.unconfigured
					if !got.Equal(want) || replace != wantReplace {
						t.Errorf("wrapped plan = %v, want %v; replacement=%v, want %v", got, want, replace, wantReplace)
					}
				})
			}
			// Each module reproduces the official replacement false positive.
			_, replace := delegatedRunModifiers(t, name, original.Attributes[name], state, plan, fixture.module(fixture.configElement), false, false, false)
			if !replace {
				t.Error("fixture did not reproduce official RequiresReplaceIfConfigured")
			}
		})
	}
}

type delegatedModuleFixture struct {
	attribute      schema.Attribute
	elementType    types.ObjectType
	prior, planned []attr.Value
	configElement  attr.Value
	changePath     []string
	changed        attr.Value
	module         func(...attr.Value) attr.Value
}

func newDelegatedModuleFixture(t *testing.T, name string, attribute schema.Attribute) delegatedModuleFixture {
	t.Helper()
	fixture := delegatedModuleFixture{attribute: attribute}
	if name == "origin_rewrite" {
		moduleType := attribute.GetType().(types.ObjectType)
		fixture.elementType = moduleType.AttrTypes["origin_rewrite_rule"].(types.SetType).ElemType.(types.ObjectType)
		fixture.module = func(elements ...attr.Value) attr.Value {
			value := certificateHTTPSObject(t, moduleType)
			value = certificateHTTPSSet(t, value, types.BoolValue(true), "switch")
			return certificateHTTPSSet(t, value, types.SetValueMust(fixture.elementType, elements), "origin_rewrite_rule")
		}
		fixture.changePath = []string{"origin_rewrite_action", "target_path"}
		fixture.changed = types.StringValue("/changed")
	} else {
		fixture.elementType = attribute.GetType().(types.SetType).ElemType.(types.ObjectType)
		fixture.module = func(elements ...attr.Value) attr.Value { return types.SetValueMust(fixture.elementType, elements) }
		fixture.changePath = []string{"cache_action", "ttl"}
		fixture.changed = types.Int64Value(9999)
		if name == "response_header" {
			fixture.changePath = []string{"response_header_action", "response_header_instances", "value"}
			fixture.changed = types.StringValue("changed")
		}
	}
	for i := 0; i < 3; i++ {
		element := certificateHTTPSObject(t, fixture.elementType)
		var computedPath []string
		switch name {
		case "cache", "browser_cache":
			element = certificateHTTPSSet(t, element, types.StringValue("cache"), "cache_action", "action")
			element = certificateHTTPSSet(t, element, types.Int64Value(int64((i+1)*3600)), "cache_action", "ttl")
			computedPath = []string{"cache_action", "default_policy"}
		case "response_header":
			actionType := fixture.elementType.AttrTypes["response_header_action"].(types.ObjectType)
			headerType := actionType.AttrTypes["response_header_instances"].(types.SetType).ElemType.(types.ObjectType)
			header := certificateHTTPSObject(t, headerType)
			header = certificateHTTPSSet(t, header, types.StringValue("set"), "action")
			header = certificateHTTPSSet(t, header, types.StringValue("X-Test"), "key")
			header = certificateHTTPSSet(t, header, types.StringValue([]string{"live-a", "live-b", "bootstrap"}[i]), "value")
			element = certificateHTTPSSet(t, element, types.SetValueMust(headerType, []attr.Value{header}), "response_header_action", "response_header_instances")
			computedPath = []string{"response_header_action", "response_header_instances", "value_type"}
		case "origin_rewrite":
			element = certificateHTTPSSet(t, element, types.StringValue("^/source"), "origin_rewrite_action", "source_path")
			element = certificateHTTPSSet(t, element, types.StringValue([]string{"/live-a", "/live-b", "/bootstrap"}[i]), "origin_rewrite_action", "target_path")
			computedPath = []string{"origin_rewrite_action", "rewrite_type"}
		}
		if i == 2 {
			fixture.configElement = element
			continue
		}
		fixture.prior = append(fixture.prior, element)
		conditionType := fixture.elementType.AttrTypes["condition"].(types.ObjectType)
		planned := certificateHTTPSSet(t, element, types.ObjectUnknown(conditionType.AttrTypes), "condition")
		planned = certificateOriginTestSet(t, planned, types.StringUnknown(), computedPath...).(types.Object)
		fixture.planned = append(fixture.planned, planned)
	}
	return fixture
}

func delegatedRunModifiers(t *testing.T, name string, attribute schema.Attribute, state, plan, config attr.Value, create, destroy, firstOnly bool) (attr.Value, bool) {
	t.Helper()
	ctx := context.Background()
	rootSchema := schema.Schema{Attributes: map[string]schema.Attribute{name: attribute}}
	rootType := types.ObjectType{AttrTypes: map[string]attr.Type{name: attribute.GetType()}}
	raw := func(value attr.Value, null bool) tftypes.Value {
		if null {
			return tftypes.NewValue(rootType.TerraformType(ctx), nil)
		}
		encoded, err := types.ObjectValueMust(rootType.AttrTypes, map[string]attr.Value{name: value}).ToTerraformValue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	prior := tfsdk.State{Schema: rootSchema, Raw: raw(state, create)}
	proposed := tfsdk.Plan{Schema: rootSchema, Raw: raw(plan, destroy)}
	configured := tfsdk.Config{Schema: rootSchema, Raw: raw(config, false)}
	switch attribute := attribute.(type) {
	case schema.SetNestedAttribute:
		req := planmodifier.SetRequest{State: prior, Plan: proposed, Config: configured, StateValue: state.(types.Set), PlanValue: plan.(types.Set), ConfigValue: config.(types.Set)}
		resp := &planmodifier.SetResponse{PlanValue: req.PlanValue}
		modifiers := attribute.PlanModifiers
		if firstOnly {
			modifiers = modifiers[:1]
		}
		for _, modifier := range modifiers {
			req.PlanValue = resp.PlanValue
			modifier.PlanModifySet(ctx, req, resp)
		}
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
		return resp.PlanValue, resp.RequiresReplace
	case schema.SingleNestedAttribute:
		req := planmodifier.ObjectRequest{State: prior, Plan: proposed, Config: configured, StateValue: state.(types.Object), PlanValue: plan.(types.Object), ConfigValue: config.(types.Object)}
		resp := &planmodifier.ObjectResponse{PlanValue: req.PlanValue}
		modifiers := attribute.PlanModifiers
		if firstOnly {
			modifiers = modifiers[:1]
		}
		for _, modifier := range modifiers {
			req.PlanValue = resp.PlanValue
			modifier.PlanModifyObject(ctx, req, resp)
		}
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
		return resp.PlanValue, resp.RequiresReplace
	default:
		t.Fatalf("unsupported delegated attribute %T", attribute)
		return nil, false
	}
}
