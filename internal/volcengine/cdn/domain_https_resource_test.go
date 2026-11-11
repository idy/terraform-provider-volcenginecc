// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestDomainHTTPSResourceSchema(t *testing.T) {
	t.Parallel()
	fixture := newDomainHTTPSResourceFixture(t)
	inner := &domainHTTPSInnerFake{schema: fixture.schema}
	wrapper := &domainHTTPSResource{Resource: inner}
	resp := &resource.SchemaResponse{}
	wrapper.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics: %v", resp.Diagnostics)
	}
	https := resp.Schema.Attributes["https"].(schema.SingleNestedAttribute)
	if len(https.PlanModifiers) != 2 {
		t.Fatalf("HTTPS modifiers = %d, want state preservation and bounded replacement", len(https.PlanModifiers))
	}
	for name, before := range fixture.schema.Attributes {
		if name == "origin" || name == "cache" || name == "browser_cache" || name == "response_header" {
			prior := before.(schema.SetNestedAttribute)
			after := resp.Schema.Attributes[name].(schema.SetNestedAttribute)
			if len(after.PlanModifiers) != len(prior.PlanModifiers)+1 {
				t.Fatalf("origin modifiers = %d, want %d", len(after.PlanModifiers), len(prior.PlanModifiers)+1)
			}
			if name == "origin" {
				if _, ok := after.PlanModifiers[0].(certificateOriginPreserveUnconfiguredModifier); !ok {
					t.Errorf("origin's first modifier = %T, want preservation before original replacement", after.PlanModifiers[0])
				}
			}
			for index, modifier := range prior.PlanModifiers {
				actual := after.PlanModifiers[index+1]
				if reflect.TypeOf(actual) != reflect.TypeOf(modifier) || actual.Description(context.Background()) != modifier.Description(context.Background()) || actual.MarkdownDescription(context.Background()) != modifier.MarkdownDescription(context.Background()) {
					t.Errorf("wrapper changed original origin modifier %d", index)
				}
			}
			// Replacement modifiers contain function closures, for which
			// reflect.DeepEqual is false even after a faithful slice copy.
			after.PlanModifiers = prior.PlanModifiers
			if !reflect.DeepEqual(prior, after) {
				t.Error("wrapper changed original origin schema")
			}
			continue
		}
		if name == "origin_rewrite" {
			prior := before.(schema.SingleNestedAttribute)
			after := resp.Schema.Attributes[name].(schema.SingleNestedAttribute)
			if len(after.PlanModifiers) != len(prior.PlanModifiers)+1 {
				t.Fatalf("%s modifiers = %d, want %d", name, len(after.PlanModifiers), len(prior.PlanModifiers)+1)
			}
			for index, modifier := range prior.PlanModifiers {
				actual := after.PlanModifiers[index+1]
				if reflect.TypeOf(actual) != reflect.TypeOf(modifier) || actual.Description(context.Background()) != modifier.Description(context.Background()) || actual.MarkdownDescription(context.Background()) != modifier.MarkdownDescription(context.Background()) {
					t.Errorf("wrapper changed original %s modifier %d", name, index)
				}
			}
			after.PlanModifiers = prior.PlanModifiers
			if !reflect.DeepEqual(prior, after) {
				t.Errorf("wrapper changed original %s schema", name)
			}
			continue
		}
		if name != "https" && !reflect.DeepEqual(before, resp.Schema.Attributes[name]) {
			t.Errorf("wrapper changed %q schema", name)
		}
	}
	for _, tc := range []struct {
		name    string
		plan    types.Object
		config  types.Object
		replace bool
	}{
		{name: "certificate-update", plan: fixture.targetHTTPS(), config: fixture.configHTTPS()},
		{name: "tls-update", plan: certificateHTTPSSet(t, fixture.targetHTTPS(), types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "tls_version"), config: fixture.configHTTPS(), replace: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := planmodifier.ObjectRequest{
				State: fixture.state, StateValue: fixture.priorHTTPS(), ConfigValue: tc.config,
				Plan: fixture.plan, PlanValue: tc.plan,
			}
			response := &planmodifier.ObjectResponse{PlanValue: tc.plan}
			for _, modifier := range https.PlanModifiers {
				request.PlanValue = response.PlanValue
				modifier.PlanModifyObject(context.Background(), request, response)
			}
			if response.Diagnostics.HasError() || response.RequiresReplace != tc.replace {
				t.Errorf("RequiresReplace = %v, want %v; diagnostics: %v", response.RequiresReplace, tc.replace, response.Diagnostics)
			}
		})
	}
}

func TestDomainHTTPSResourceModifyPlan(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		unknownID  bool
		encryption bool
		noChange   bool
		tlsChange  bool
		metadata   bool
		mutualCA   bool
		create     bool
		destroy    bool
		clear      bool
	}{
		{name: "known-renewal", clear: true},
		{name: "unknown-renewal", unknownID: true, clear: true},
		{name: "explicit-ordinary-encryption-preserved", encryption: true, clear: true},
		{name: "mutual-ca-null-material-unknown-plan-retains-prior-set", mutualCA: true, clear: true},
		{name: "no-op", noChange: true},
		{name: "tls-change-retains-official-plan", tlsChange: true},
		{name: "explicit-metadata-retains-official-plan", metadata: true},
		{name: "create", create: true},
		{name: "delete", destroy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := newDomainHTTPSResourceFixture(t)
			planRoot, configRoot := fixture.planRoot, fixture.configRoot
			if tc.mutualCA {
				stateCA, planCA, configCA := certificateMutualCAFixture(t)
				fixture.stateRoot = certificateHTTPSSet(t, fixture.stateRoot, types.BoolValue(true), "https", "cert_check", "switch")
				fixture.stateRoot = certificateHTTPSSet(t, fixture.stateRoot, stateCA, "https", "cert_check", "cert_info_list")
				fixture.state.Raw = domainHTTPSRaw(t, fixture.stateRoot)
				planRoot = certificateHTTPSSet(t, planRoot, types.BoolValue(true), "https", "cert_check", "switch")
				planRoot = certificateHTTPSSet(t, planRoot, planCA, "https", "cert_check", "cert_info_list")
				planRoot = certificateHTTPSSet(t, planRoot, types.SetUnknown(types.StringType), "https", "tls_version")
				configRoot = certificateHTTPSSet(t, configRoot, types.BoolValue(true), "https", "cert_check", "switch")
				configRoot = certificateHTTPSSet(t, configRoot, configCA, "https", "cert_check", "cert_info_list")
			}
			if tc.unknownID {
				planRoot = certificateHTTPSSet(t, planRoot, types.StringUnknown(), "https", "cert_info", "cert_id")
				configRoot = certificateHTTPSSet(t, configRoot, types.StringUnknown(), "https", "cert_info", "cert_id")
			}
			if tc.encryption {
				configRoot = certificateHTTPSSet(t, configRoot, types.StringValue("inter_cert"), "https", "cert_info", "encry_type")
			}
			if tc.noChange {
				planRoot = fixture.stateRoot
				configRoot = certificateHTTPSSet(t, configRoot, types.StringValue("cert_hosting-old"), "https", "cert_info", "cert_id")
			}
			if tc.tlsChange {
				planRoot = certificateHTTPSSet(t, planRoot, types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "https", "tls_version")
			}
			if tc.metadata {
				configRoot = certificateHTTPSSet(t, configRoot, types.StringValue("old.example"), "https", "cert_info", "cert_name")
			}
			state := fixture.state
			if tc.create {
				state.Raw = tftypes.NewValue(fixture.schema.Type().TerraformType(context.Background()), nil)
			}
			plan := tfsdk.Plan{Schema: fixture.schema, Raw: domainHTTPSRaw(t, planRoot)}
			if tc.destroy {
				plan.Raw = tftypes.NewValue(fixture.schema.Type().TerraformType(context.Background()), nil)
			}
			inner := &domainHTTPSInnerFake{schema: fixture.schema}
			wrapper := &domainHTTPSResource{Resource: inner}
			resp := &resource.ModifyPlanResponse{}
			wrapper.ModifyPlan(context.Background(), resource.ModifyPlanRequest{
				State: state, Plan: plan,
				Config: tfsdk.Config{Schema: fixture.schema, Raw: domainHTTPSRaw(t, configRoot)},
			}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("ModifyPlan diagnostics: %v", resp.Diagnostics)
			}
			if inner.modifyCalls != 1 {
				t.Errorf("inner ModifyPlan calls = %d, want 1", inner.modifyCalls)
			}
			if !tc.clear {
				if !resp.Plan.Raw.Equal(plan.Raw) {
					t.Error("non-certificate plan was changed")
				}
				return
			}
			var https types.Object
			resp.Diagnostics.Append(resp.Plan.GetAttribute(context.Background(), path.Root("https"), &https)...)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			cert := https.Attributes()["cert_info"].(types.Object)
			for _, name := range []string{"cert_name", "effective_time", "expire_time", "encry_type", "certificate"} {
				wantUnknown := name != "encry_type" || !tc.encryption
				if cert.Attributes()[name].IsUnknown() != wantUnknown {
					t.Errorf("cert_info.%s unknown = %v, want %v", name, cert.Attributes()[name].IsUnknown(), wantUnknown)
				}
			}
			before := planRoot.Attributes()["https"].(types.Object)
			beforeCert := before.Attributes()["cert_info"].(types.Object)
			for _, name := range []string{"cert_id", "source"} {
				if !cert.Attributes()[name].Equal(beforeCert.Attributes()[name]) {
					t.Errorf("ModifyPlan changed configured %s", name)
				}
			}
			priorHTTPS := fixture.stateRoot.Attributes()["https"].(types.Object)
			for name, value := range priorHTTPS.Attributes() {
				if name != "cert_info" && !value.Equal(https.Attributes()[name]) {
					t.Errorf("ModifyPlan failed to preserve prior HTTPS %s", name)
				}
			}
			if tc.mutualCA {
				check := https.Attributes()["cert_check"].(types.Object)
				caList := check.Attributes()["cert_info_list"].(types.Set)
				caRaw, err := caList.ToTerraformValue(context.Background())
				if err != nil || !caRaw.IsFullyKnown() {
					t.Error("CA set still contains unknown metadata after server certificate planning")
				}
				for _, value := range caList.Elements() {
					if !value.(types.Object).Attributes()["certificate"].IsNull() {
						t.Error("prior CA certificate=null was not preserved")
					}
				}
			}
			var updated types.Int64
			resp.Diagnostics.Append(resp.Plan.GetAttribute(context.Background(), path.Root("updated_time"), &updated)...)
			if !updated.IsUnknown() {
				t.Error("updated_time remains known during rotation")
			}
			for _, name := range []string{"id", "domain", "cname"} {
				var got types.String
				resp.Diagnostics.Append(resp.Plan.GetAttribute(context.Background(), path.Root(name), &got)...)
				if !got.Equal(planRoot.Attributes()[name]) {
					t.Errorf("ModifyPlan changed %s", name)
				}
			}
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
		})
	}
}

func TestDomainHTTPSResourceUpdate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		alreadyTarget bool
		configuring   bool
		writeError    bool
		verifyError   bool
		readError     bool
		readNull      bool
		readLag       int
		neverConverge bool
		identityDrift string
		planIdentity  string
		tlsChange     bool
		sameBinding   bool
		unknownID     bool
		nilAPI        bool
		wantError     bool
		wantWrites    int
		wantReads     int
		wantObserve   int
		wantVerify    int
	}{
		{name: "success-retains-id-cname", wantWrites: 1, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "native-write-failure-retains-prior-state", writeError: true, wantError: true, wantWrites: 1, wantObserve: 1, wantVerify: 1},
		{name: "native-verification-failure-retains-prior-state", verifyError: true, wantError: true, wantObserve: 1, wantVerify: 1},
		{name: "already-target-zero-write-recovery", alreadyTarget: true, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "already-target-configuring-zero-write-recovery", alreadyTarget: true, configuring: true, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "old-binding-configuring-blocks-write", configuring: true, wantError: true, wantObserve: 1},
		{name: "cloud-control-readback-lag", readLag: 2, wantWrites: 1, wantReads: 3, wantObserve: 3, wantVerify: 2},
		{name: "cloud-control-never-converges", neverConverge: true, wantError: true, wantWrites: 1, wantReads: 4, wantObserve: 3, wantVerify: 2},
		{name: "cloud-control-read-error", readError: true, wantError: true, wantWrites: 1, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "cloud-control-domain-missing", readNull: true, wantError: true, wantWrites: 1, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "cloud-control-id-drift", identityDrift: "id", wantError: true, wantWrites: 1, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "cloud-control-cname-drift", identityDrift: "cname", wantError: true, wantWrites: 1, wantReads: 1, wantObserve: 3, wantVerify: 2},
		{name: "planned-domain-change-rejected", planIdentity: "domain", wantError: true},
		{name: "planned-id-change-rejected", planIdentity: "id", wantError: true},
		{name: "planned-cname-change-rejected", planIdentity: "cname", wantError: true},
		{name: "tls-and-certificate-change-rejected", tlsChange: true, wantError: true},
		{name: "tls-change-same-certificate-rejected", tlsChange: true, sameBinding: true, wantError: true},
		{name: "unknown-id-at-apply-rejected", unknownID: true, wantError: true},
		{name: "unconfigured-native-client-rejected", nilAPI: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			fixture := newDomainHTTPSResourceFixture(t)
			planRoot := fixture.planRoot
			configRoot := fixture.configRoot
			if tc.sameBinding {
				planRoot = fixture.stateRoot
				configRoot = certificateHTTPSSet(t, configRoot, types.StringValue("cert_hosting-old"), "https", "cert_info", "cert_id")
			}
			if tc.tlsChange {
				planRoot = certificateHTTPSSet(t, planRoot, types.SetValueMust(types.StringType, []attr.Value{types.StringValue("tlsv1.3")}), "https", "tls_version")
			}
			if tc.unknownID {
				planRoot = certificateHTTPSSet(t, planRoot, types.StringUnknown(), "https", "cert_info", "cert_id")
				configRoot = certificateHTTPSSet(t, configRoot, types.StringUnknown(), "https", "cert_info", "cert_id")
			}
			if tc.planIdentity != "" {
				planRoot = certificateHTTPSSet(t, planRoot, types.StringValue("different-identity"), tc.planIdentity)
			}
			inner := &domainHTTPSInnerFake{schema: fixture.schema}
			observed := fixture.targetRoot
			if tc.identityDrift != "" {
				observed = certificateHTTPSSet(t, observed, types.StringValue("different-live-identity"), tc.identityDrift)
			}
			for index := 0; index < tc.readLag; index++ {
				inner.readStates = append(inner.readStates, fixture.state)
			}
			readState := tfsdk.State{Schema: fixture.schema, Raw: domainHTTPSRaw(t, observed)}
			if tc.neverConverge {
				readState = fixture.state
			}
			if tc.readNull {
				readState.Raw = tftypes.NewValue(fixture.schema.Type().TerraformType(ctx), nil)
			}
			inner.readStates = append(inner.readStates, readState)
			if tc.readError {
				inner.readError = errors.New("synthetic Cloud Control read error")
			}
			before, target := fixture.observation(false), fixture.observation(true)
			if tc.alreadyTarget {
				before = target
			}
			if tc.configuring {
				before.Status = "configuring"
			}
			api := &domainHTTPSAPIFake{observations: []httpsObservation{before, target, target}}
			if tc.writeError {
				api.writeError = errors.New("synthetic native write error")
			}
			if tc.verifyError {
				api.verifyError = errors.New("synthetic certificate inventory error")
			}
			waits := 0
			wrapper := &domainHTTPSResource{Resource: inner, api: api, attempts: 4, wait: func(context.Context) error { waits++; return nil }}
			if tc.nilAPI {
				wrapper.api = nil
			}
			config := tfsdk.Config{Schema: fixture.schema, Raw: domainHTTPSRaw(t, configRoot)}
			modify := &resource.ModifyPlanResponse{}
			wrapper.ModifyPlan(ctx, resource.ModifyPlanRequest{
				State: fixture.state, Config: config, Plan: tfsdk.Plan{Schema: fixture.schema, Raw: domainHTTPSRaw(t, planRoot)},
			}, modify)
			if modify.Diagnostics.HasError() {
				t.Fatal(modify.Diagnostics)
			}
			resp := &resource.UpdateResponse{}
			wrapper.Update(ctx, resource.UpdateRequest{State: fixture.state, Plan: modify.Plan, Config: config}, resp)
			if resp.Diagnostics.HasError() != tc.wantError {
				t.Errorf("Update error = %v, want %v; diagnostics: %v", resp.Diagnostics.HasError(), tc.wantError, resp.Diagnostics)
			}
			if inner.createCalls != 0 || inner.deleteCalls != 0 || inner.updateCalls != 0 {
				t.Errorf("inner mutations: Create=%d Update=%d Delete=%d; want none", inner.createCalls, inner.updateCalls, inner.deleteCalls)
			}
			if api.writeCalls != tc.wantWrites || inner.readCalls != tc.wantReads || api.observeCalls != tc.wantObserve || api.verifyCalls != tc.wantVerify {
				t.Errorf("calls write/read/observe/verify = %d/%d/%d/%d, want %d/%d/%d/%d", api.writeCalls, inner.readCalls, api.observeCalls, api.verifyCalls, tc.wantWrites, tc.wantReads, tc.wantObserve, tc.wantVerify)
			}
			if tc.wantError {
				if !resp.State.Raw.Equal(fixture.state.Raw) {
					t.Error("failed update did not preserve the prior state")
				}
				return
			}
			if !resp.State.Raw.Equal(domainHTTPSRaw(t, fixture.targetRoot)) {
				t.Error("updated state does not match the Cloud Control projection with refreshed metadata")
			}
			for _, name := range []string{"domain", "id", "cname"} {
				var value types.String
				diagnostics := resp.State.GetAttribute(ctx, path.Root(name), &value)
				if diagnostics.HasError() || !value.Equal(fixture.stateRoot.Attributes()[name]) {
					t.Errorf("identity %s changed after certificate update", name)
				}
			}
			if tc.readLag > 0 && waits < tc.readLag {
				t.Errorf("Cloud Control lag did not use the bounded wait hook: waits = %d", waits)
			}
			if tc.wantWrites != 0 {
				payload := api.payload
				https := payload["HTTPS"].(map[string]interface{})
				cert := https["CertInfo"].(map[string]interface{})
				if payload["Domain"] != "cdn.example" || cert["CertId"] != "cert_hosting-new" || cert["Source"] != "volc_cert_center" || https["HTTP2"] != true {
					t.Errorf("unexpected native update payload: %#v", payload)
				}
			}
		})
	}
}

type domainHTTPSResourceFixture struct {
	schema                          schema.Schema
	stateRoot, planRoot, targetRoot types.Object
	configRoot                      types.Object
	state                           tfsdk.State
	plan                            tfsdk.Plan
}

func newDomainHTTPSResourceFixture(t *testing.T) domainHTTPSResourceFixture {
	t.Helper()
	ctx := context.Background()
	base := newCertificateHTTPSFixture(t)
	inner, err := domainResource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	response := &resource.SchemaResponse{}
	inner.Schema(ctx, resource.SchemaRequest{}, response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	attributes := make(map[string]schema.Attribute)
	for _, name := range []string{"https", "origin", "cache", "browser_cache", "response_header", "origin_rewrite", "domain", "id", "cname", "updated_time"} {
		attributes[name] = response.Schema.Attributes[name]
	}
	fixture := domainHTTPSResourceFixture{schema: schema.Schema{Attributes: attributes}}
	originType := attributes["origin"].GetType().(types.SetType)
	originElementType := originType.ElemType.(types.ObjectType)
	originActionType := originElementType.AttrTypes["origin_action"].(types.ObjectType)
	originLineType := originActionType.AttrTypes["origin_lines"].(types.SetType).ElemType.(types.ObjectType)
	originLine := certificateHTTPSObject(t, originLineType)
	for name, value := range map[string]attr.Value{
		"address": types.StringValue("origin.example"), "instance_type": types.StringValue("domain"), "origin_type": types.StringValue("primary"),
		"http_port": types.StringValue("80"), "https_port": types.StringValue("443"), "weight": types.StringValue("1"),
		"origin_host": types.StringValue(""), "private_bucket_access": types.BoolValue(false),
	} {
		originLine = certificateHTTPSSet(t, originLine, value, name)
	}
	originElement := certificateHTTPSSet(t, certificateHTTPSObject(t, originElementType), types.SetValueMust(originLineType, []attr.Value{originLine}), "origin_action", "origin_lines")
	originValue := types.SetValueMust(originElementType, []attr.Value{originElement})
	fixture.stateRoot = certificateHTTPSObject(t, fixture.schema.Type().(types.ObjectType))
	fixture.stateRoot = certificateHTTPSSet(t, fixture.stateRoot, originValue, "origin")
	for name, value := range map[string]attr.Value{
		"https": base.state, "domain": types.StringValue("cdn.example"), "id": types.StringValue("cdn.example"),
		"cname": types.StringValue("cdn.example.cdn.invalid"), "updated_time": types.Int64Value(1000),
	} {
		fixture.stateRoot = certificateHTTPSSet(t, fixture.stateRoot, value, name)
	}
	fixture.planRoot = certificateHTTPSSet(t, fixture.stateRoot, types.StringValue("cert_hosting-new"), "https", "cert_info", "cert_id")
	fixture.targetRoot = fixture.planRoot
	for _, item := range []struct {
		value attr.Value
		path  []string
	}{
		{types.StringValue("new.example"), []string{"https", "cert_info", "cert_name"}},
		{types.Int64Value(200), []string{"https", "cert_info", "effective_time"}},
		{types.Int64Value(300), []string{"https", "cert_info", "expire_time"}},
		{types.Int64Value(2000), []string{"updated_time"}},
	} {
		fixture.targetRoot = certificateHTTPSSet(t, fixture.targetRoot, item.value, item.path...)
	}
	fixture.configRoot = certificateHTTPSObject(t, fixture.schema.Type().(types.ObjectType))
	fixture.configRoot = certificateHTTPSSet(t, fixture.configRoot, base.config, "https")
	fixture.configRoot = certificateHTTPSSet(t, fixture.configRoot, originValue, "origin")
	fixture.configRoot = certificateHTTPSSet(t, fixture.configRoot, types.StringValue("cert_hosting-new"), "https", "cert_info", "cert_id")
	fixture.configRoot = certificateHTTPSSet(t, fixture.configRoot, types.StringValue("cdn.example"), "domain")
	fixture.state = tfsdk.State{Schema: fixture.schema, Raw: domainHTTPSRaw(t, fixture.stateRoot)}
	fixture.plan = tfsdk.Plan{Schema: fixture.schema, Raw: domainHTTPSRaw(t, fixture.planRoot)}
	return fixture
}

func (fixture domainHTTPSResourceFixture) priorHTTPS() types.Object {
	return fixture.stateRoot.Attributes()["https"].(types.Object)
}

func (fixture domainHTTPSResourceFixture) targetHTTPS() types.Object {
	return fixture.planRoot.Attributes()["https"].(types.Object)
}

func (fixture domainHTTPSResourceFixture) configHTTPS() types.Object {
	return fixture.configRoot.Attributes()["https"].(types.Object)
}

func (fixture domainHTTPSResourceFixture) observation(target bool) httpsObservation {
	binding := certificateBinding{ID: "cert_hosting-old", Source: "volc_cert_center"}
	if target {
		binding.ID = "cert_hosting-new"
	}
	return httpsObservation{
		Domain: "cdn.example", Project: "test-project", CNAME: "cdn.example.cdn.invalid", Status: "online", Binding: binding,
		HTTPS: map[string]interface{}{
			"Switch": true, "HTTP2": true,
			"TlsVersion": []interface{}{"tlsv1.1", "tlsv1.2", "tlsv1.3"},
			"CertInfo":   map[string]interface{}{"CertId": binding.ID, "Source": binding.Source, "EncryType": "inter_cert"},
		},
	}
}

func domainHTTPSRaw(t *testing.T, value types.Object) tftypes.Value {
	t.Helper()
	raw, err := value.ToTerraformValue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type domainHTTPSInnerFake struct {
	schema                                           schema.Schema
	readStates                                       []tfsdk.State
	readError                                        error
	createCalls, readCalls, updateCalls, deleteCalls int
	modifyCalls                                      int
}

func (inner *domainHTTPSInnerFake) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "volcenginecc_cdn_domain"
}

func (inner *domainHTTPSInnerFake) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attributes := make(map[string]schema.Attribute, len(inner.schema.Attributes))
	for name, attribute := range inner.schema.Attributes {
		attributes[name] = attribute
	}
	resp.Schema = inner.schema
	resp.Schema.Attributes = attributes
}

func (inner *domainHTTPSInnerFake) Create(_ context.Context, _ resource.CreateRequest, resp *resource.CreateResponse) {
	inner.createCalls++
	resp.Diagnostics.AddError("Unexpected inner Create", "Certificate updates must retain the existing domain.")
}

func (inner *domainHTTPSInnerFake) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	inner.deleteCalls++
	resp.Diagnostics.AddError("Unexpected inner Delete", "Certificate updates must retain the existing domain.")
}

func (inner *domainHTTPSInnerFake) Update(_ context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	inner.updateCalls++
	resp.State = tfsdk.State{Schema: req.Plan.Schema, Raw: req.Plan.Raw}
}

func (inner *domainHTTPSInnerFake) Read(_ context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	index := inner.readCalls
	inner.readCalls++
	if inner.readError != nil {
		resp.Diagnostics.AddError("Synthetic read failure", inner.readError.Error())
		return
	}
	if index >= len(inner.readStates) {
		index = len(inner.readStates) - 1
	}
	if index < 0 {
		resp.Diagnostics.AddError("Unexpected Read", "No Cloud Control projection was supplied.")
		return
	}
	resp.State = inner.readStates[index]
}

func (inner *domainHTTPSInnerFake) ModifyPlan(_ context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	inner.modifyCalls++
	resp.Plan = req.Plan
}

type domainHTTPSAPIFake struct {
	observations                          []httpsObservation
	writeError, verifyError               error
	observeCalls, verifyCalls, writeCalls int
	payload                               map[string]interface{}
}

func (api *domainHTTPSAPIFake) Observe(_ context.Context, _ string) (httpsObservation, error) {
	index := api.observeCalls
	api.observeCalls++
	if index >= len(api.observations) {
		index = len(api.observations) - 1
	}
	if index < 0 {
		return httpsObservation{}, errors.New("unexpected native observation")
	}
	return api.observations[index], nil
}

func (api *domainHTTPSAPIFake) Verify(_ context.Context, _ string, _ certificateBinding) error {
	api.verifyCalls++
	return api.verifyError
}

func (api *domainHTTPSAPIFake) Update(_ context.Context, _ string, payload map[string]interface{}) error {
	api.writeCalls++
	api.payload = payload
	return api.writeError
}
