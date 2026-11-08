// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestDomainHTTPSHydrationRejectsKnownDrift(t *testing.T) {
	ctx := context.Background()
	s := schema.Schema{Attributes: map[string]schema.Attribute{
		"id":           schema.StringAttribute{Computed: true},
		"http2":        schema.BoolAttribute{Optional: true},
		"updated_time": schema.Int64Attribute{Computed: true},
	}}
	typeOf := s.Type().TerraformType(ctx)
	plan := tfsdk.Plan{Schema: s, Raw: tftypes.NewValue(typeOf, map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, "same-id"),
		"http2":        tftypes.NewValue(tftypes.Bool, true),
		"updated_time": tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
	})}
	observed := tfsdk.State{Schema: s, Raw: tftypes.NewValue(typeOf, map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, "same-id"),
		"http2":        tftypes.NewValue(tftypes.Bool, false),
		"updated_time": tftypes.NewValue(tftypes.Number, int64(200)),
	})}
	if _, err := hydrateHTTPSPlan(ctx, plan, observed); err == nil {
		t.Fatal("known remote drift was replaced by the saved plan in state")
	}
	observed.Raw = tftypes.NewValue(typeOf, map[string]tftypes.Value{
		"id":           tftypes.NewValue(tftypes.String, "same-id"),
		"http2":        tftypes.NewValue(tftypes.Bool, true),
		"updated_time": tftypes.NewValue(tftypes.Number, int64(200)),
	})
	state, err := hydrateHTTPSPlan(ctx, plan, observed)
	if err != nil || !state.Raw.Equal(observed.Raw) {
		t.Fatalf("computed readback hydration failed: %v", err)
	}
}
