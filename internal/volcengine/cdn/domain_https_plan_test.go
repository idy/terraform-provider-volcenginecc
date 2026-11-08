// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Use the actual generated schema, rather than a hand-maintained approximation:
// every fixture contains the real Optional+Computed nested attributes and types.
func TestCertificateHTTPSPlan(t *testing.T) {
	t.Parallel()
	fixture := newCertificateHTTPSFixture(t)
	type change struct {
		where string
		path  []string
		value attr.Value
	}
	set := func(where string, value attr.Value, path ...string) change {
		return change{where: where, path: path, value: value}
	}
	unknownTLS := types.SetUnknown(types.StringType)
	emptyList := types.SetValueMust(fixture.certType, nil)
	dualList := types.SetValueMust(fixture.certType, []attr.Value{fixture.state.Attributes()["cert_info"]})
	unknownList := types.SetUnknown(fixture.certType)
	unknownMaterial := types.ObjectUnknown(fixture.materialType.AttrTypes)
	unknownCert := types.ObjectUnknown(fixture.certType.AttrTypes)

	cases := []struct {
		name            string
		changes         []change
		bindingChange   bool
		requiresReplace bool
		create, destroy bool
	}{
		{name: "no-op"},
		{name: "known-new-id", changes: []change{set("plan", types.StringValue("cert_hosting-new"), "cert_info", "cert_id"), set("config", types.StringValue("cert_hosting-new"), "cert_info", "cert_id")}, bindingChange: true},
		{name: "unknown-new-id", changes: []change{set("plan", types.StringUnknown(), "cert_info", "cert_id"), set("config", types.StringUnknown(), "cert_info", "cert_id")}, bindingChange: true},
		{name: "source-change", changes: []change{set("plan", types.StringValue("cdn_cert_hosting"), "cert_info", "source"), set("config", types.StringValue("cdn_cert_hosting"), "cert_info", "source")}, bindingChange: true},
		{name: "unknown-id-with-source-change", changes: []change{set("plan", types.StringUnknown(), "cert_info", "cert_id"), set("config", types.StringUnknown(), "cert_info", "cert_id"), set("plan", types.StringValue("cdn_cert_hosting"), "cert_info", "source"), set("config", types.StringValue("cdn_cert_hosting"), "cert_info", "source")}, bindingChange: true},
		{name: "unknown-source", changes: []change{set("plan", types.StringUnknown(), "cert_info", "source"), set("config", types.StringUnknown(), "cert_info", "source")}, requiresReplace: true},
		{name: "unsupported-source", changes: []change{set("plan", types.StringValue("other"), "cert_info", "source"), set("config", types.StringValue("other"), "cert_info", "source")}, requiresReplace: true},
		{name: "id-change-not-configured", changes: []change{set("plan", types.StringValue("cert_hosting-new"), "cert_info", "cert_id"), set("config", types.StringNull(), "cert_info", "cert_id")}, requiresReplace: true},
		{name: "source-change-not-configured", changes: []change{set("plan", types.StringValue("cdn_cert_hosting"), "cert_info", "source"), set("config", types.StringNull(), "cert_info", "source")}, requiresReplace: true},
		{name: "empty-id", changes: []change{set("plan", types.StringValue(""), "cert_info", "cert_id"), set("config", types.StringValue(""), "cert_info", "cert_id")}, requiresReplace: true},
		{name: "null-id", changes: []change{set("plan", types.StringNull(), "cert_info", "cert_id"), set("config", types.StringNull(), "cert_info", "cert_id")}, requiresReplace: true},
		{name: "unknown-cert-info", changes: []change{set("plan", unknownCert, "cert_info"), set("config", unknownCert, "cert_info")}, requiresReplace: true},
		{name: "https-disabled", changes: []change{set("plan", types.BoolValue(false), "switch"), set("config", types.BoolValue(false), "switch")}, requiresReplace: true},
		{name: "https-enabled", changes: []change{set("state", types.BoolValue(false), "switch")}, requiresReplace: true},
		{name: "https-switch-unknown", changes: []change{set("plan", types.BoolUnknown(), "switch"), set("config", types.BoolUnknown(), "switch")}, requiresReplace: true},
		{name: "tls-change", changes: []change{set("plan", types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "tls_version"), set("config", types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "tls_version")}, requiresReplace: true},
		{name: "explicit-unknown-tls", changes: []change{set("plan", unknownTLS, "tls_version"), set("config", unknownTLS, "tls_version")}, requiresReplace: true},
		{name: "redirect-switch-change", changes: []change{set("plan", types.BoolValue(true), "forced_redirect", "enable_forced_redirect"), set("config", types.BoolValue(true), "forced_redirect", "enable_forced_redirect")}, requiresReplace: true},
		{name: "redirect-code-change", changes: []change{set("plan", types.StringValue("302"), "forced_redirect", "status_code"), set("config", types.StringValue("302"), "forced_redirect", "status_code")}, requiresReplace: true},
		{name: "http2-change", changes: []change{set("plan", types.BoolValue(false), "http2"), set("config", types.BoolValue(false), "http2")}, requiresReplace: true},
		{name: "ocsp-change", changes: []change{set("plan", types.BoolValue(true), "ocsp"), set("config", types.BoolValue(true), "ocsp")}, requiresReplace: true},
		{name: "disable-http-change", changes: []change{set("plan", types.BoolValue(true), "disable_http"), set("config", types.BoolValue(true), "disable_http")}, requiresReplace: true},
		{name: "hsts-change", changes: []change{set("plan", types.Int64Value(1000), "hsts", "ttl"), set("config", types.Int64Value(1000), "hsts", "ttl")}, requiresReplace: true},
		{name: "cert-check-change", changes: []change{set("plan", types.BoolValue(true), "cert_check", "switch"), set("config", types.BoolValue(true), "cert_check", "switch")}, requiresReplace: true},
		{name: "metadata-unknown-no-binding-change", changes: []change{set("plan", types.StringUnknown(), "cert_info", "cert_name"), set("plan", types.Int64Unknown(), "cert_info", "effective_time"), set("plan", types.Int64Unknown(), "cert_info", "expire_time")}},
		{name: "computed-metadata-new-value-no-binding-change", changes: []change{set("plan", types.StringValue("new-cn.example"), "cert_info", "cert_name")}},
		{name: "configured-metadata-unchanged-no-binding-change", changes: []change{set("config", types.StringValue("old.example"), "cert_info", "cert_name")}},
		{name: "configured-metadata-changed", changes: []change{set("plan", types.StringValue("new.example"), "cert_info", "cert_name"), set("config", types.StringValue("new.example"), "cert_info", "cert_name")}, requiresReplace: true},
		{name: "configured-metadata-unknown", changes: []change{set("plan", types.StringUnknown(), "cert_info", "cert_name"), set("config", types.StringUnknown(), "cert_info", "cert_name")}, requiresReplace: true},
		{name: "create", create: true},
		{name: "delete", destroy: true},
		{name: "unconfigured-https", changes: []change{set("config", types.ObjectNull(fixture.httpsType.AttrTypes)), set("plan", types.ObjectUnknown(fixture.httpsType.AttrTypes))}},
		{name: "add-https-to-existing-resource", changes: []change{set("state", types.ObjectNull(fixture.httpsType.AttrTypes))}, requiresReplace: true},
		{name: "unknown-https", changes: []change{set("plan", types.ObjectUnknown(fixture.httpsType.AttrTypes)), set("config", types.ObjectUnknown(fixture.httpsType.AttrTypes))}, requiresReplace: true},
	}

	// Repeat the restrictions together with an otherwise eligible rotation.
	rotation := []change{set("plan", types.StringUnknown(), "cert_info", "cert_id"), set("config", types.StringUnknown(), "cert_info", "cert_id")}
	rotationCases := []struct {
		name    string
		changes []change
		allowed bool
	}{
		{name: "computed-metadata-unknown", changes: []change{set("plan", types.StringUnknown(), "cert_info", "cert_name"), set("plan", types.Int64Unknown(), "cert_info", "effective_time"), set("plan", types.Int64Unknown(), "cert_info", "expire_time"), set("plan", types.StringUnknown(), "cert_info", "encry_type"), set("plan", unknownMaterial, "cert_info", "certificate")}, allowed: true},
		{name: "computed-metadata-new-values", changes: []change{set("plan", types.StringValue("new.example"), "cert_info", "cert_name"), set("plan", types.Int64Value(300), "cert_info", "effective_time"), set("plan", types.Int64Value(400), "cert_info", "expire_time")}, allowed: true},
		{name: "computed-defaults-unknown", changes: []change{set("plan", types.BoolUnknown(), "http2"), set("plan", unknownTLS, "tls_version"), set("plan", types.StringUnknown(), "forced_redirect", "status_code"), set("plan", types.BoolUnknown(), "hsts", "switch"), set("plan", unknownList, "cert_info_list")}, allowed: true},
		{name: "previously-null-computed-defaults-unknown", changes: []change{set("state", types.BoolNull(), "ocsp"), set("plan", types.BoolUnknown(), "ocsp"), set("state", types.ObjectNull(fixture.materialType.AttrTypes), "cert_info", "certificate"), set("plan", unknownMaterial, "cert_info", "certificate")}, allowed: true},
		{name: "source-omitted-retains-state", changes: []change{set("config", types.StringNull(), "cert_info", "source"), set("plan", types.StringUnknown(), "cert_info", "source")}, allowed: true},
		{name: "ordinary-encryption-default", changes: []change{set("state", types.StringNull(), "cert_info", "encry_type"), set("plan", types.StringUnknown(), "cert_info", "encry_type")}, allowed: true},
		{name: "explicit-ordinary-encryption", changes: []change{set("config", types.StringValue("inter_cert"), "cert_info", "encry_type")}, allowed: true},
		{name: "empty-dual-cert-list", changes: []change{set("plan", emptyList, "cert_info_list"), set("config", emptyList, "cert_info_list")}, allowed: true},
		{name: "dual-cert-in-state", changes: []change{set("state", dualList, "cert_info_list"), set("plan", dualList, "cert_info_list")}},
		{name: "dual-cert-in-plan", changes: []change{set("plan", dualList, "cert_info_list")}},
		{name: "dual-cert-in-config", changes: []change{set("config", dualList, "cert_info_list")}},
		{name: "explicit-unknown-dual-cert", changes: []change{set("plan", unknownList, "cert_info_list"), set("config", unknownList, "cert_info_list")}},
		{name: "state-sm-encryption", changes: []change{set("state", types.StringValue("sm_cert"), "cert_info", "encry_type"), set("plan", types.StringUnknown(), "cert_info", "encry_type")}},
		{name: "planned-sm-encryption", changes: []change{set("plan", types.StringValue("sm_cert"), "cert_info", "encry_type")}},
		{name: "configured-sm-encryption", changes: []change{set("config", types.StringValue("sm_cert"), "cert_info", "encry_type")}},
		{name: "configured-unknown-encryption", changes: []change{set("config", types.StringUnknown(), "cert_info", "encry_type"), set("plan", types.StringUnknown(), "cert_info", "encry_type")}},
		{name: "configured-name-even-unchanged", changes: []change{set("config", types.StringValue("old.example"), "cert_info", "cert_name")}},
		{name: "configured-effective-time-even-unchanged", changes: []change{set("config", types.Int64Value(100), "cert_info", "effective_time")}},
		{name: "configured-expiry-even-unchanged", changes: []change{set("config", types.Int64Value(200), "cert_info", "expire_time")}},
		{name: "tls-change", changes: []change{set("plan", types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "tls_version")}},
		{name: "explicit-unknown-tls", changes: []change{set("plan", unknownTLS, "tls_version"), set("config", unknownTLS, "tls_version")}},
		{name: "redirect-change", changes: []change{set("plan", types.BoolValue(true), "forced_redirect", "enable_forced_redirect")}},
		{name: "https-disabled", changes: []change{set("plan", types.BoolValue(false), "switch")}},
		{name: "no-existing-id", changes: []change{set("state", types.StringNull(), "cert_info", "cert_id")}},
		{name: "unknown-prior-id", changes: []change{set("state", types.StringUnknown(), "cert_info", "cert_id"), set("plan", types.StringValue("cert_hosting-new"), "cert_info", "cert_id"), set("config", types.StringValue("cert_hosting-new"), "cert_info", "cert_id")}},
	}
	for _, field := range []string{"certificate", "private_key", "encryption_cert", "encryption_key"} {
		for _, where := range []string{"state", "plan", "config"} {
			rotationCases = append(rotationCases, struct {
				name    string
				changes []change
				allowed bool
			}{name: where + "-embedded-" + field, changes: []change{set(where, types.StringValue("embedded-material"), "cert_info", "certificate", field)}})
		}
	}
	for _, tc := range rotationCases {
		cases = append(cases, struct {
			name            string
			changes         []change
			bindingChange   bool
			requiresReplace bool
			create, destroy bool
		}{name: "rotation/" + tc.name, changes: append(append([]change(nil), rotation...), tc.changes...), bindingChange: tc.allowed, requiresReplace: !tc.allowed})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state, plan, config := fixture.state, fixture.state, fixture.config
			for _, change := range tc.changes {
				target := &plan
				switch change.where {
				case "state":
					target = &state
				case "config":
					target = &config
				}
				*target = certificateHTTPSSet(t, *target, change.value, change.path...)
			}
			if tc.create {
				state = types.ObjectNull(fixture.httpsType.AttrTypes)
			}
			if tc.destroy {
				plan = types.ObjectNull(fixture.httpsType.AttrTypes)
			}
			if got := certificateOnlyHTTPSChange(state, plan, config); got != tc.bindingChange {
				t.Errorf("certificateOnlyHTTPSChange() = %v, want %v", got, tc.bindingChange)
			}
			req := planmodifier.ObjectRequest{
				StateValue: state, PlanValue: plan, ConfigValue: config,
				State: tfsdk.State{Schema: fixture.schema, Raw: fixture.raw(t, state, tc.create)},
				Plan:  tfsdk.Plan{Schema: fixture.schema, Raw: fixture.raw(t, plan, tc.destroy)},
			}
			resp := &planmodifier.ObjectResponse{PlanValue: plan}
			certificateHTTPSRequiresReplace().PlanModifyObject(context.Background(), req, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			if resp.RequiresReplace != tc.requiresReplace {
				t.Errorf("RequiresReplace = %v, want %v", resp.RequiresReplace, tc.requiresReplace)
			}
			if !resp.PlanValue.Equal(plan) {
				t.Error("replacement modifier changed the planned HTTPS value")
			}
		})
	}
}

type certificateHTTPSFixture struct {
	schema                            schema.Schema
	httpsType, certType, materialType types.ObjectType
	state, config                     types.Object
}

func newCertificateHTTPSFixture(t *testing.T) certificateHTTPSFixture {
	t.Helper()
	ctx := context.Background()
	r, err := domainResource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read generated schema: %v", resp.Diagnostics)
	}
	https := resp.Schema.Attributes["https"].(schema.SingleNestedAttribute)
	fixture := certificateHTTPSFixture{
		schema:    schema.Schema{Attributes: map[string]schema.Attribute{"https": https}},
		httpsType: https.GetType().(types.ObjectType),
	}
	fixture.certType = fixture.httpsType.AttrTypes["cert_info"].(types.ObjectType)
	fixture.materialType = fixture.certType.AttrTypes["certificate"].(types.ObjectType)
	fixture.state = certificateHTTPSObject(t, fixture.httpsType)
	for _, item := range []struct {
		path  []string
		value attr.Value
	}{
		{[]string{"switch"}, types.BoolValue(true)},
		{[]string{"http2"}, types.BoolValue(true)},
		{[]string{"ocsp"}, types.BoolValue(false)},
		{[]string{"disable_http"}, types.BoolValue(false)},
		{[]string{"tls_version"}, types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.1"), types.StringValue("tlsv1.2"), types.StringValue("tlsv1.3")})},
		{[]string{"forced_redirect", "enable_forced_redirect"}, types.BoolValue(false)},
		{[]string{"forced_redirect", "status_code"}, types.StringValue("301")},
		{[]string{"hsts", "switch"}, types.BoolValue(false)},
		{[]string{"hsts", "subdomain"}, types.StringValue("exclude")},
		{[]string{"hsts", "ttl"}, types.Int64Value(0)},
		{[]string{"cert_check", "switch"}, types.BoolValue(false)},
		{[]string{"cert_info", "cert_id"}, types.StringValue("cert_hosting-old")},
		{[]string{"cert_info", "source"}, types.StringValue("volc_cert_center")},
		{[]string{"cert_info", "encry_type"}, types.StringValue("inter_cert")},
		{[]string{"cert_info", "cert_name"}, types.StringValue("old.example")},
		{[]string{"cert_info", "effective_time"}, types.Int64Value(100)},
		{[]string{"cert_info", "expire_time"}, types.Int64Value(200)},
	} {
		fixture.state = certificateHTTPSSet(t, fixture.state, item.value, item.path...)
	}
	fixture.config = certificateHTTPSObject(t, fixture.httpsType)
	fixture.config = certificateHTTPSSet(t, fixture.config, types.BoolValue(true), "switch")
	fixture.config = certificateHTTPSSet(t, fixture.config, types.StringValue("cert_hosting-old"), "cert_info", "cert_id")
	fixture.config = certificateHTTPSSet(t, fixture.config, types.StringValue("volc_cert_center"), "cert_info", "source")
	return fixture
}

func certificateHTTPSObject(t *testing.T, typ types.ObjectType) types.Object {
	t.Helper()
	values := make(map[string]attr.Value, len(typ.AttrTypes))
	for name, typ := range typ.AttrTypes {
		value, err := typ.ValueFromTerraform(context.Background(), tftypes.NewValue(typ.TerraformType(context.Background()), nil))
		if err != nil {
			t.Fatal(err)
		}
		values[name] = value
	}
	return types.ObjectValueMust(typ.AttrTypes, values)
}

func certificateHTTPSSet(t *testing.T, object types.Object, value attr.Value, path ...string) types.Object {
	t.Helper()
	if len(path) == 0 {
		return value.(types.Object)
	}
	if object.IsNull() {
		object = certificateHTTPSObject(t, types.ObjectType{AttrTypes: object.AttributeTypes(context.Background())})
	}
	values := object.Attributes()
	if len(path) == 1 {
		values[path[0]] = value
	} else {
		values[path[0]] = certificateHTTPSSet(t, values[path[0]].(types.Object), value, path[1:]...)
	}
	return types.ObjectValueMust(object.AttributeTypes(context.Background()), values)
}

func (fixture certificateHTTPSFixture) raw(t *testing.T, https types.Object, nullResource bool) tftypes.Value {
	t.Helper()
	typ := types.ObjectType{AttrTypes: map[string]attr.Type{"https": fixture.httpsType}}
	if nullResource {
		return tftypes.NewValue(typ.TerraformType(context.Background()), nil)
	}
	root := types.ObjectValueMust(typ.AttrTypes, map[string]attr.Value{"https": https})
	value, err := root.ToTerraformValue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCertificateOriginPreserveUnconfigured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	resourceValue, err := domainResource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resourceSchema := &resource.SchemaResponse{}
	resourceValue.Schema(ctx, resource.SchemaRequest{}, resourceSchema)
	if resourceSchema.Diagnostics.HasError() {
		t.Fatal(resourceSchema.Diagnostics)
	}
	origin := resourceSchema.Schema.Attributes["origin"].(schema.SetNestedAttribute)
	originType := origin.GetType().(types.SetType)
	elementType := originType.ElemType.(types.ObjectType)
	actionType := elementType.AttrTypes["origin_action"].(types.ObjectType)
	linesType := actionType.AttrTypes["origin_lines"].(types.SetType)
	lineType := linesType.ElemType.(types.ObjectType)
	conditionType := elementType.AttrTypes["condition"].(types.ObjectType)
	stateLine := certificateHTTPSObject(t, lineType)
	configLine := certificateHTTPSObject(t, lineType)
	for name, value := range map[string]attr.Value{
		"address": types.StringValue("origin.example"), "instance_type": types.StringValue("domain"), "origin_type": types.StringValue("primary"),
	} {
		stateLine = certificateHTTPSSet(t, stateLine, value, name)
		configLine = certificateHTTPSSet(t, configLine, value, name)
	}
	for name, value := range map[string]attr.Value{
		"http_port": types.StringValue("80"), "https_port": types.StringValue("443"), "weight": types.StringValue("1"),
		"origin_host": types.StringValue(""), "private_bucket_access": types.BoolValue(false),
	} {
		stateLine = certificateHTTPSSet(t, stateLine, value, name)
	}
	stateElement := certificateHTTPSSet(t, certificateHTTPSObject(t, elementType), types.SetValueMust(lineType, []attr.Value{stateLine}), "origin_action", "origin_lines")
	configElement := certificateHTTPSSet(t, certificateHTTPSObject(t, elementType), types.SetValueMust(lineType, []attr.Value{configLine}), "origin_action", "origin_lines")
	state := types.SetValueMust(elementType, []attr.Value{stateElement})
	config := types.SetValueMust(elementType, []attr.Value{configElement})
	plan := certificateOriginTestSet(t, state, types.ObjectUnknown(conditionType.AttrTypes), "condition").(types.Set)
	plan = certificateOriginTestSet(t, plan, types.StringUnknown(), "origin_action", "origin_lines", "region").(types.Set)
	rootSchema := schema.Schema{Attributes: map[string]schema.Attribute{"origin": origin}}
	rootType := types.ObjectType{AttrTypes: map[string]attr.Type{"origin": originType}}
	raw := func(value types.Set, nullResource bool) tftypes.Value {
		if nullResource {
			return tftypes.NewValue(rootType.TerraformType(ctx), nil)
		}
		root := types.ObjectValueMust(rootType.AttrTypes, map[string]attr.Value{"origin": value})
		encoded, err := root.ToTerraformValue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	type change struct {
		where string
		value attr.Value
		path  []string
	}
	set := func(where string, value attr.Value, path ...string) change {
		return change{where: where, value: value, path: path}
	}
	secondState := certificateHTTPSSet(t, stateElement, types.SetValueMust(lineType, []attr.Value{certificateHTTPSSet(t, stateLine, types.StringValue("backup.example"), "address")}), "origin_action", "origin_lines")
	secondConfig := certificateHTTPSSet(t, configElement, types.SetValueMust(lineType, []attr.Value{certificateHTTPSSet(t, configLine, types.StringValue("backup.example"), "address")}), "origin_action", "origin_lines")
	secondPlan := certificateHTTPSSet(t, secondState, types.ObjectUnknown(conditionType.AttrTypes), "condition")
	cases := []struct {
		name            string
		changes         []change
		preserve        bool
		requiresReplace bool
		create, destroy bool
	}{
		{name: "null-computed-condition-and-region-to-unknown", preserve: true},
		{name: "omitted-private-auth-unknown", changes: []change{set("plan", types.ObjectUnknown(lineType.AttrTypes["private_bucket_auth"].(types.ObjectType).AttrTypes), "origin_action", "origin_lines", "private_bucket_auth")}, preserve: true},
		{name: "explicit-port-unchanged", changes: []change{set("config", types.StringValue("443"), "origin_action", "origin_lines", "https_port")}, preserve: true},
		{name: "explicit-region-unchanged", changes: []change{set("state", types.StringValue("cn-beijing"), "origin_action", "origin_lines", "region"), set("plan", types.StringValue("cn-beijing"), "origin_action", "origin_lines", "region"), set("config", types.StringValue("cn-beijing"), "origin_action", "origin_lines", "region")}, preserve: true},
		{name: "address-change", changes: []change{set("plan", types.StringValue("new-origin.example"), "origin_action", "origin_lines", "address"), set("config", types.StringValue("new-origin.example"), "origin_action", "origin_lines", "address")}, requiresReplace: true},
		{name: "known-planned-address-diff-even-with-old-config", changes: []change{set("plan", types.StringValue("new-origin.example"), "origin_action", "origin_lines", "address")}, requiresReplace: true},
		{name: "weight-change", changes: []change{set("plan", types.StringValue("2"), "origin_action", "origin_lines", "weight"), set("config", types.StringValue("2"), "origin_action", "origin_lines", "weight")}, requiresReplace: true},
		{name: "http-port-change", changes: []change{set("plan", types.StringValue("8080"), "origin_action", "origin_lines", "http_port"), set("config", types.StringValue("8080"), "origin_action", "origin_lines", "http_port")}, requiresReplace: true},
		{name: "https-port-change", changes: []change{set("plan", types.StringValue("8443"), "origin_action", "origin_lines", "https_port"), set("config", types.StringValue("8443"), "origin_action", "origin_lines", "https_port")}, requiresReplace: true},
		{name: "known-computed-port-diff-not-hidden", changes: []change{set("plan", types.StringValue("8080"), "origin_action", "origin_lines", "http_port")}, requiresReplace: true},
		{name: "origin-host-change", changes: []change{set("plan", types.StringValue("origin-host.example"), "origin_action", "origin_lines", "origin_host"), set("config", types.StringValue("origin-host.example"), "origin_action", "origin_lines", "origin_host")}, requiresReplace: true},
		{name: "private-bucket-access-change", changes: []change{set("plan", types.BoolValue(true), "origin_action", "origin_lines", "private_bucket_access"), set("config", types.BoolValue(true), "origin_action", "origin_lines", "private_bucket_access")}, requiresReplace: true},
		{name: "instance-type-change", changes: []change{set("plan", types.StringValue("tos"), "origin_action", "origin_lines", "instance_type"), set("config", types.StringValue("tos"), "origin_action", "origin_lines", "instance_type")}, requiresReplace: true},
		{name: "origin-type-change", changes: []change{set("plan", types.StringValue("backup"), "origin_action", "origin_lines", "origin_type"), set("config", types.StringValue("backup"), "origin_action", "origin_lines", "origin_type")}, requiresReplace: true},
		{name: "condition-added", changes: []change{set("plan", types.StringValue("AND"), "condition", "connective"), set("config", types.StringValue("AND"), "condition", "connective")}, requiresReplace: true},
		{name: "condition-changed", changes: []change{set("state", types.StringValue("OR"), "condition", "connective"), set("plan", types.StringValue("AND"), "condition", "connective"), set("config", types.StringValue("AND"), "condition", "connective")}, requiresReplace: true},
		{name: "condition-explicitly-unchanged", changes: []change{set("state", types.StringValue("OR"), "condition", "connective"), set("plan", types.StringValue("OR"), "condition", "connective"), set("config", types.StringValue("OR"), "condition", "connective")}, preserve: true},
		{name: "unknown-config-address", changes: []change{set("config", types.StringUnknown(), "origin_action", "origin_lines", "address"), set("plan", types.StringUnknown(), "origin_action", "origin_lines", "address")}, requiresReplace: true},
		{name: "unknown-config-descendant-even-when-plan-address-known", changes: []change{set("config", types.StringUnknown(), "origin_action", "origin_lines", "address")}, requiresReplace: true},
		{name: "unknown-config-condition", changes: []change{set("config", types.ObjectUnknown(conditionType.AttrTypes), "condition")}, requiresReplace: true},
		{name: "unknown-config-origin-action", changes: []change{set("config", types.ObjectUnknown(actionType.AttrTypes), "origin_action")}, requiresReplace: true},
		{name: "unknown-config-lines", changes: []change{set("config", types.SetUnknown(lineType), "origin_action", "origin_lines")}, requiresReplace: true},
		{name: "unknown-config-root", changes: []change{set("config", types.SetUnknown(elementType))}, requiresReplace: true},
		{name: "unknown-planned-configured-port", changes: []change{set("config", types.StringValue("443"), "origin_action", "origin_lines", "https_port"), set("plan", types.StringUnknown(), "origin_action", "origin_lines", "https_port")}, requiresReplace: true},
		{name: "multiple-origins-unique-projection", changes: []change{set("state", types.SetValueMust(elementType, []attr.Value{stateElement, secondState})), set("plan", types.SetValueMust(elementType, []attr.Value{secondPlan, plan.Elements()[0]})), set("config", types.SetValueMust(elementType, []attr.Value{configElement, secondConfig}))}, preserve: true},
		{name: "multiple-origin-lines-unique-projection", changes: []change{set("state", types.SetValueMust(lineType, []attr.Value{stateLine, certificateHTTPSSet(t, stateLine, types.StringValue("backup.example"), "address")}), "origin_action", "origin_lines"), set("plan", types.SetValueMust(lineType, []attr.Value{certificateHTTPSSet(t, stateLine, types.StringValue("backup.example"), "address"), stateLine}), "origin_action", "origin_lines"), set("config", types.SetValueMust(lineType, []attr.Value{configLine, certificateHTTPSSet(t, configLine, types.StringValue("backup.example"), "address")}), "origin_action", "origin_lines")}, preserve: true},
		{name: "unknown-prior-value-falls-back", changes: []change{set("state", types.StringUnknown(), "origin_action", "origin_lines", "region")}, requiresReplace: true},
		{name: "create", create: true},
		{name: "delete", destroy: true},
	}
	backupState := certificateHTTPSSet(t, certificateHTTPSSet(t, stateLine, types.StringValue("backup.example"), "address"), types.StringValue("backup"), "origin_type")
	backupConfig := certificateHTTPSSet(t, certificateHTTPSSet(t, configLine, types.StringValue("backup.example"), "address"), types.StringValue("backup"), "origin_type")
	primaryPlan := certificateHTTPSSet(t, stateLine, types.StringUnknown(), "region")
	backupPlan := certificateHTTPSSet(t, backupState, types.StringUnknown(), "region")
	withLines := func(where string, values ...attr.Value) change {
		return set(where, types.SetValueMust(lineType, values), "origin_action", "origin_lines")
	}
	primaryBackup := []change{withLines("state", stateLine, backupState), withLines("plan", backupPlan, primaryPlan), withLines("config", configLine, backupConfig)}
	cases = append(cases, struct {
		name            string
		changes         []change
		preserve        bool
		requiresReplace bool
		create, destroy bool
	}{name: "primary-backup-unknown-region-null-condition-reordered", changes: primaryBackup, preserve: true})
	for _, field := range []string{"address", "weight", "http_port", "https_port"} {
		changed := types.StringValue("changed-" + field)
		changes := []change{
			withLines("state", stateLine, backupState),
			withLines("plan", certificateHTTPSSet(t, backupPlan, changed, field), primaryPlan),
			withLines("config", configLine, certificateHTTPSSet(t, backupConfig, changed, field)),
		}
		cases = append(cases, struct {
			name            string
			changes         []change
			preserve        bool
			requiresReplace bool
			create, destroy bool
		}{name: "primary-backup-real-" + field + "-change", changes: changes, requiresReplace: true})
	}
	for _, tc := range []struct {
		name    string
		changes []change
	}{
		{"primary-backup-config-unknown", []change{withLines("state", stateLine, backupState), withLines("plan", primaryPlan, certificateHTTPSSet(t, backupPlan, types.StringUnknown(), "weight")), withLines("config", configLine, certificateHTTPSSet(t, backupConfig, types.StringUnknown(), "weight"))}},
		{"origin-line-added", []change{withLines("plan", primaryPlan, backupPlan), withLines("config", configLine, backupConfig)}},
		{"origin-line-removed", []change{withLines("state", stateLine, backupState)}},
		{"origin-added", []change{set("plan", types.SetValueMust(elementType, []attr.Value{plan.Elements()[0], secondPlan})), set("config", types.SetValueMust(elementType, []attr.Value{configElement, secondConfig}))}},
		{"origin-removed", []change{set("state", types.SetValueMust(elementType, []attr.Value{stateElement, secondState}))}},
		{"ambiguous-line-config-projections", []change{
			withLines("state", certificateHTTPSSet(t, stateLine, types.StringValue("host-a.example"), "origin_host"), certificateHTTPSSet(t, stateLine, types.StringValue("host-b.example"), "origin_host")),
			withLines("plan", certificateHTTPSSet(t, primaryPlan, types.StringValue("host-b.example"), "origin_host"), certificateHTTPSSet(t, primaryPlan, types.StringValue("host-a.example"), "origin_host")),
			withLines("config", configLine, certificateHTTPSSet(t, configLine, types.StringValue("1"), "weight")),
		}},
	} {
		cases = append(cases, struct {
			name            string
			changes         []change
			preserve        bool
			requiresReplace bool
			create, destroy bool
		}{name: tc.name, changes: tc.changes, requiresReplace: true})
	}
	// Nested condition-rule sets also use configured projections, preserving
	// unknown omitted names without relying on rule order.
	ruleType := conditionType.AttrTypes["condition_rule"].(types.SetType).ElemType.(types.ObjectType)
	rule := certificateHTTPSObject(t, ruleType)
	for name, value := range map[string]attr.Value{"type": types.StringValue("url"), "object": types.StringValue("path"), "operator": types.StringValue("match"), "value": types.StringValue("/a/*")} {
		rule = certificateHTTPSSet(t, rule, value, name)
	}
	ruleB := certificateHTTPSSet(t, rule, types.StringValue("/b/*"), "value")
	conditionState := certificateHTTPSSet(t, certificateHTTPSObject(t, conditionType), types.SetValueMust(ruleType, []attr.Value{rule, ruleB}), "condition_rule")
	conditionState = certificateHTTPSSet(t, conditionState, types.StringValue("OR"), "connective")
	conditionPlan := certificateHTTPSSet(t, conditionState, types.SetValueMust(ruleType, []attr.Value{certificateHTTPSSet(t, ruleB, types.StringUnknown(), "name"), certificateHTTPSSet(t, rule, types.StringUnknown(), "name")}), "condition_rule")
	for _, tc := range []struct {
		name                string
		planned, configured types.Object
		preserve            bool
	}{
		{"condition-rules-reordered-computed-names-unknown", conditionPlan, conditionState, true},
		{"condition-rule-real-change", certificateHTTPSSet(t, conditionState, types.SetValueMust(ruleType, []attr.Value{rule, certificateHTTPSSet(t, ruleB, types.StringValue("/changed/*"), "value")}), "condition_rule"), certificateHTTPSSet(t, conditionState, types.SetValueMust(ruleType, []attr.Value{rule, certificateHTTPSSet(t, ruleB, types.StringValue("/changed/*"), "value")}), "condition_rule"), false},
		{"condition-rule-config-unknown", conditionPlan, certificateHTTPSSet(t, conditionState, types.SetValueMust(ruleType, []attr.Value{rule, certificateHTTPSSet(t, ruleB, types.StringUnknown(), "value")}), "condition_rule"), false},
	} {
		cases = append(cases, struct {
			name            string
			changes         []change
			preserve        bool
			requiresReplace bool
			create, destroy bool
		}{name: tc.name, changes: []change{set("state", conditionState, "condition"), set("plan", tc.planned, "condition"), set("config", tc.configured, "condition")}, preserve: tc.preserve, requiresReplace: !tc.preserve})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, p, c := state, plan, config
			for _, change := range tc.changes {
				target := &p
				switch change.where {
				case "state":
					target = &s
				case "config":
					target = &c
				}
				*target = certificateOriginTestSet(t, *target, change.value, change.path...).(types.Set)
			}
			if tc.create {
				s = types.SetNull(elementType)
			}
			if tc.destroy {
				p = types.SetNull(elementType)
			}
			req := planmodifier.SetRequest{
				StateValue: s, PlanValue: p, ConfigValue: c,
				State: tfsdk.State{Schema: rootSchema, Raw: raw(s, tc.create)},
				Plan:  tfsdk.Plan{Schema: rootSchema, Raw: raw(p, tc.destroy)},
			}
			resp := &planmodifier.SetResponse{PlanValue: p}
			certificateOriginPreserveUnconfigured().PlanModifySet(ctx, req, resp)
			want := p
			if tc.preserve {
				want = s
			}
			if !resp.PlanValue.Equal(want) {
				t.Errorf("origin plan preservation = %v, want %v", resp.PlanValue, want)
			}
			// Run the actual generated replacement modifier after preservation.
			for _, modifier := range origin.PlanModifiers {
				req.PlanValue = resp.PlanValue
				modifier.PlanModifySet(ctx, req, resp)
			}
			if resp.Diagnostics.HasError() || resp.RequiresReplace != tc.requiresReplace {
				t.Errorf("RequiresReplace = %v, want %v; diagnostics: %v", resp.RequiresReplace, tc.requiresReplace, resp.Diagnostics)
			}
		})
	}

	// The existing upstream modifier does require replacement for this exact
	// null-to-unknown fixture without the new preservation step.
	request := planmodifier.SetRequest{
		StateValue: state, PlanValue: plan, ConfigValue: config,
		State: tfsdk.State{Schema: rootSchema, Raw: raw(state, false)},
		Plan:  tfsdk.Plan{Schema: rootSchema, Raw: raw(plan, false)},
	}
	response := &planmodifier.SetResponse{PlanValue: plan}
	setplanmodifier.RequiresReplace().PlanModifySet(ctx, request, response)
	if !response.RequiresReplace {
		t.Error("fixture did not reproduce upstream replacement for unconfigured computed unknowns")
	}
}

// Descend only singleton sets; test fixtures never rely on set element order.
func certificateOriginTestSet(t *testing.T, value attr.Value, replacement attr.Value, path ...string) attr.Value {
	t.Helper()
	if len(path) == 0 {
		return replacement
	}
	switch value := value.(type) {
	case types.Object:
		if value.IsNull() || value.IsUnknown() {
			value = certificateHTTPSObject(t, types.ObjectType{AttrTypes: value.AttributeTypes(context.Background())})
		}
		attributes := value.Attributes()
		attributes[path[0]] = certificateOriginTestSet(t, attributes[path[0]], replacement, path[1:]...)
		return types.ObjectValueMust(value.AttributeTypes(context.Background()), attributes)
	case types.Set:
		if len(value.Elements()) != 1 {
			t.Fatal("test fixture edit requires a singleton set")
		}
		return types.SetValueMust(value.ElementType(context.Background()), []attr.Value{certificateOriginTestSet(t, value.Elements()[0], replacement, path...)})
	default:
		t.Fatalf("cannot descend origin test value %T", value)
		return nil
	}
}

func TestCertificateHTTPSMutualAuthentication(t *testing.T) {
	t.Parallel()
	fixture := newCertificateHTTPSFixture(t)
	stateCA, planCA, configCA := certificateMutualCAFixture(t)
	certType := stateCA.ElementType(context.Background()).(types.ObjectType)
	stateA, stateB := stateCA.Elements()[0].(types.Object), stateCA.Elements()[1].(types.Object)
	planA, planB := planCA.Elements()[0].(types.Object), planCA.Elements()[1].(types.Object)
	configA, configB := configCA.Elements()[0].(types.Object), configCA.Elements()[1].(types.Object)
	set := func(values ...attr.Value) types.Set { return types.SetValueMust(certType, values) }
	// Both explicit projections below match both prior certificates. Distinct
	// known validity metadata keeps the planned elements separate, so rejection
	// must come from ambiguous configuration matching rather than cardinality.
	ambiguousStateB := certificateHTTPSSet(t, stateA, types.Int64Value(1234), "effective_time")
	ambiguousPlanA := certificateHTTPSSet(t, stateA, types.StringUnknown(), "cert_name")
	ambiguousPlanB := certificateHTTPSSet(t, ambiguousStateB, types.StringUnknown(), "cert_name")
	for _, tc := range []struct {
		name      string
		state     types.Set
		plan      types.Set
		config    types.Set
		allowed   bool
		noBinding bool
	}{
		{name: "ca-metadata-unknown", state: stateCA, plan: planCA, config: configCA, allowed: true},
		{name: "ca-metadata-unknown-without-binding-change", state: stateCA, plan: planCA, config: configCA, allowed: true, noBinding: true},
		{name: "ca-sets-reordered", state: set(stateB, stateA), plan: set(planA, planB), config: set(configB, configA), allowed: true},
		{name: "ca-id-change", state: stateCA, plan: set(certificateHTTPSSet(t, planA, types.StringValue("ca-new"), "cert_id"), planB), config: set(certificateHTTPSSet(t, configA, types.StringValue("ca-new"), "cert_id"), configB)},
		{name: "ca-source-change", state: stateCA, plan: set(certificateHTTPSSet(t, planA, types.StringValue("cdn_cert_hosting"), "source"), planB), config: set(certificateHTTPSSet(t, configA, types.StringValue("cdn_cert_hosting"), "source"), configB)},
		{name: "ca-explicit-unknown-id", state: stateCA, plan: set(certificateHTTPSSet(t, planA, types.StringUnknown(), "cert_id"), planB), config: set(certificateHTTPSSet(t, configA, types.StringUnknown(), "cert_id"), configB)},
		{name: "ca-explicit-unknown-descendant-even-when-plan-known", state: stateCA, plan: planCA, config: set(certificateHTTPSSet(t, configA, types.StringUnknown(), "cert_name"), configB)},
		{name: "ca-known-metadata-difference-not-hidden", state: stateCA, plan: set(certificateHTTPSSet(t, planA, types.StringValue("changed-cn.example"), "cert_name"), planB), config: configCA},
		{name: "ca-added", state: set(stateA), plan: planCA, config: configCA},
		{name: "ca-removed", state: stateCA, plan: set(planA), config: set(configA)},
		{name: "ca-ambiguous-config-projections", state: set(stateA, ambiguousStateB), plan: set(ambiguousPlanB, ambiguousPlanA), config: set(configA, certificateHTTPSSet(t, configA, types.StringValue("inter_cert"), "encry_type"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state, plan, config := fixture.state, fixture.state, fixture.config
			for _, target := range []*types.Object{&state, &plan, &config} {
				*target = certificateHTTPSSet(t, *target, types.BoolValue(true), "cert_check", "switch")
			}
			state = certificateHTTPSSet(t, state, tc.state, "cert_check", "cert_info_list")
			plan = certificateHTTPSSet(t, plan, tc.plan, "cert_check", "cert_info_list")
			config = certificateHTTPSSet(t, config, tc.config, "cert_check", "cert_info_list")
			if !tc.noBinding {
				plan = certificateHTTPSSet(t, plan, types.StringValue("cert_hosting-new"), "cert_info", "cert_id")
				config = certificateHTTPSSet(t, config, types.StringValue("cert_hosting-new"), "cert_info", "cert_id")
			}
			if got := certificateOnlyHTTPSChange(state, plan, config); got != (tc.allowed && !tc.noBinding) {
				t.Errorf("certificate-only admission = %v, want %v", got, tc.allowed && !tc.noBinding)
			}
			req := planmodifier.ObjectRequest{
				StateValue: state, PlanValue: plan, ConfigValue: config,
				State: tfsdk.State{Schema: fixture.schema, Raw: fixture.raw(t, state, false)},
				Plan:  tfsdk.Plan{Schema: fixture.schema, Raw: fixture.raw(t, plan, false)},
			}
			resp := &planmodifier.ObjectResponse{PlanValue: plan}
			certificateHTTPSRequiresReplace().PlanModifyObject(context.Background(), req, resp)
			if resp.Diagnostics.HasError() || resp.RequiresReplace != !tc.allowed {
				t.Errorf("RequiresReplace = %v, want %v; diagnostics: %v", resp.RequiresReplace, !tc.allowed, resp.Diagnostics)
			}
		})
	}
}

func certificateMutualCAFixture(t *testing.T) (types.Set, types.Set, types.Set) {
	t.Helper()
	base := newCertificateHTTPSFixture(t)
	checkType := base.httpsType.AttrTypes["cert_check"].(types.ObjectType)
	certType := checkType.AttrTypes["cert_info_list"].(types.SetType).ElemType.(types.ObjectType)
	materialType := certType.AttrTypes["certificate"].(types.ObjectType)
	var prior, planned, configured []attr.Value
	for _, id := range []string{"ca-a", "ca-b"} {
		state, config := certificateHTTPSObject(t, certType), certificateHTTPSObject(t, certType)
		for name, value := range map[string]attr.Value{"cert_id": types.StringValue(id), "source": types.StringValue("volc_cert_center")} {
			state = certificateHTTPSSet(t, state, value, name)
			config = certificateHTTPSSet(t, config, value, name)
		}
		for name, value := range map[string]attr.Value{
			"cert_name": types.StringValue(id + ".example"), "encry_type": types.StringValue("inter_cert"),
			"effective_time": types.Int64Value(1000), "expire_time": types.Int64Value(2000),
		} {
			state = certificateHTTPSSet(t, state, value, name)
		}
		plan := state
		for name, value := range map[string]attr.Value{
			"cert_name": types.StringUnknown(), "encry_type": types.StringUnknown(), "certificate": types.ObjectUnknown(materialType.AttrTypes),
			"effective_time": types.Int64Unknown(), "expire_time": types.Int64Unknown(),
		} {
			plan = certificateHTTPSSet(t, plan, value, name)
		}
		prior, planned, configured = append(prior, state), append(planned, plan), append(configured, config)
	}
	return types.SetValueMust(certType, prior), types.SetValueMust(certType, planned), types.SetValueMust(certType, configured)
}

func TestCertificatePlanUniqueSetMatching(t *testing.T) {
	t.Parallel()
	// Exhaust every three-by-three bipartite graph against the six possible
	// perfect matchings, validating both uniqueness and alternating-cycle checks.
	permutations := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for graph := 0; graph < 1<<9; graph++ {
		accepts := func(left, right int) bool { return graph&(1<<(left*3+right)) != 0 }
		count := 0
		for _, permutation := range permutations {
			if accepts(0, permutation[0]) && accepts(1, permutation[1]) && accepts(2, permutation[2]) {
				count++
			}
		}
		comparison := certificatePlanComparison{ctx: context.Background(), remaining: 100000}
		match, unique := comparison.uniqueMatch(3, accepts)
		if unique != (count == 1) {
			t.Fatalf("graph %09b unique = %v, perfect matching count = %d", graph, unique, count)
		}
		if unique {
			for left, right := range match {
				if !accepts(left, right) {
					t.Fatalf("graph %09b returned an invalid matching", graph)
				}
			}
		}
	}
	comparison := certificatePlanComparison{ctx: context.Background(), remaining: 100000}
	if _, unique := comparison.uniqueMatch(certificatePlanMaxSet+1, func(left, right int) bool { return left == right }); unique {
		t.Error("oversized set comparison did not fall back")
	}
	values := types.SetValueMust(types.StringType, []attr.Value{types.StringValue("a"), types.StringValue("b")})
	comparison.remaining = 2
	if comparison.unchanged(values, values, values) {
		t.Error("exhausted recursive comparison budget did not fall back")
	}
}
