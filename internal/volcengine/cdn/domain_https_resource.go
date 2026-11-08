// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/volcengine/terraform-provider-volcenginecc/internal/customresources"
	tfcloudcontrol "github.com/volcengine/terraform-provider-volcenginecc/internal/service/cloudcontrol"
)

func init() {
	customresources.Register("volcenginecc_cdn_domain", func(_ context.Context, inner resource.Resource) (resource.Resource, error) {
		return &domainHTTPSResource{Resource: inner}, nil
	})
}

// Only single-certificate binding changes use the native CDN API. The inner
// resource retains domain creation/deletion, imports, refresh and all other
// replacement rules; no second Terraform owner or state migration is needed.
type domainHTTPSResource struct {
	resource.Resource
	api      httpsCertificateAPI
	wait     func(context.Context) error
	attempts int
}

func (r *domainHTTPSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	r.Resource.Schema(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}
	https, ok := resp.Schema.Attributes["https"].(schema.SingleNestedAttribute)
	if !ok {
		resp.Diagnostics.AddError("Unexpected CDN schema", "The HTTPS module is not a single nested attribute.")
		return
	}
	https.PlanModifiers = []planmodifier.Object{objectplanmodifier.UseStateForUnknown(), certificateHTTPSRequiresReplace()}
	resp.Schema.Attributes["https"] = https
	origin, ok := resp.Schema.Attributes["origin"].(schema.SetNestedAttribute)
	if !ok {
		resp.Diagnostics.AddError("Unexpected CDN schema", "The origin module is not a nested set.")
		return
	}
	origin.PlanModifiers = append([]planmodifier.Set{certificateOriginPreserveUnconfigured()}, origin.PlanModifiers...)
	resp.Schema.Attributes["origin"] = origin
}

func (r *domainHTTPSResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if inner, ok := r.Resource.(resource.ResourceWithConfigure); ok {
		inner.Configure(ctx, req, resp)
	}
	if resp.Diagnostics.HasError() || req.ProviderData == nil {
		return
	}
	provider, ok := req.ProviderData.(tfcloudcontrol.Provider)
	if !ok || provider.CloudControlAPIClient(ctx) == nil {
		resp.Diagnostics.AddError("Missing CDN client configuration", "The configured Cloud Control credential chain is unavailable.")
		return
	}
	var err error
	r.api, err = newNativeHTTPSClient(&provider.CloudControlAPIClient(ctx).Config)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure native CDN client", err.Error())
	}
}

func (r *domainHTTPSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if inner, ok := r.Resource.(resource.ResourceWithImportState); ok {
		inner.ImportState(ctx, req, resp)
	}
}

func (r *domainHTTPSResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	if inner, ok := r.Resource.(resource.ResourceWithConfigValidators); ok {
		return inner.ConfigValidators(ctx)
	}
	return nil
}

func (r *domainHTTPSResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	resp.Plan = req.Plan
	if inner, ok := r.Resource.(resource.ResourceWithModifyPlan); ok {
		inner.ModifyPlan(ctx, req, resp)
	}
	if resp.Diagnostics.HasError() || req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var prior, planned, configured types.Object
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("https"), &prior)...)
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("https"), &planned)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("https"), &configured)...)
	if resp.Diagnostics.HasError() || !certificateOnlyHTTPSChange(prior, planned, configured) {
		return
	}
	cert := planned.Attributes()["cert_info"].(types.Object)
	configCert := configured.Attributes()["cert_info"].(types.Object)
	values := cert.Attributes()
	for key, value := range values {
		if key == "cert_id" || key == "source" {
			continue
		}
		if configuredValue := configCert.Attributes()[key]; configuredValue.IsNull() {
			unknown, err := value.Type(ctx).ValueFromTerraform(ctx, tftypes.NewValue(value.Type(ctx).TerraformType(ctx), tftypes.UnknownValue))
			if err != nil {
				resp.Diagnostics.AddError("Unable to plan certificate metadata", "The certificate metadata type could not be preserved.")
				return
			}
			values[key] = unknown
		}
	}
	metadata := types.ObjectValueMust(cert.AttributeTypes(ctx), values)
	httpsValues := planned.Attributes()
	for key, value := range prior.Attributes() {
		if key != "cert_info" {
			// These settings were proven unchanged by the narrow admission test.
			// Preserve whole CA/TLS sets so computed nulls inside set elements do
			// not become unknown identities during readback hydration.
			httpsValues[key] = value
		}
	}
	httpsValues["cert_info"] = metadata
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("https"), types.ObjectValueMust(planned.AttributeTypes(ctx), httpsValues))...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("updated_time"), types.Int64Unknown())...)
}

func httpsBinding(value types.Object) (certificateBinding, error) {
	if value.IsNull() || value.IsUnknown() {
		return certificateBinding{}, errors.New("HTTPS binding must be known")
	}
	cert, ok := value.Attributes()["cert_info"].(types.Object)
	if !ok || cert.IsNull() || cert.IsUnknown() {
		return certificateBinding{}, errors.New("a single known certificate binding is required")
	}
	id, idOK := cert.Attributes()["cert_id"].(types.String)
	source, sourceOK := cert.Attributes()["source"].(types.String)
	binding := certificateBinding{ID: id.ValueString(), Source: source.ValueString()}
	if !idOK || !sourceOK || id.IsNull() || id.IsUnknown() || source.IsNull() || source.IsUnknown() || !bindingValid(binding) {
		return certificateBinding{}, errors.New("certificate ID and source must resolve before updating the CDN")
	}
	return binding, nil
}

func (r *domainHTTPSResource) pause(ctx context.Context) error {
	if r.wait != nil {
		return r.wait(ctx)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (r *domainHTTPSResource) maxAttempts() int {
	if r.attempts > 0 {
		return r.attempts
	}
	return 150
}

func (r *domainHTTPSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var prior, planned, configured types.Object
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("https"), &prior)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("https"), &planned)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("https"), &configured)...)
	if resp.Diagnostics.HasError() {
		resp.State = req.State
		return
	}
	oldBinding, oldErr := httpsBinding(prior)
	newBinding, newErr := httpsBinding(planned)
	if oldErr == nil && newErr == nil && oldBinding == newBinding && certificateHTTPSUnchanged(prior, planned, configured) {
		r.Resource.Update(ctx, req, resp)
		return
	}
	resp.State = req.State
	if !certificateOnlyHTTPSChange(prior, planned, configured) || oldErr != nil || newErr != nil || r.api == nil {
		resp.Diagnostics.AddError("Unsupported CDN HTTPS update", "Only a known single-certificate binding may change in place; the domain was not changed.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var domain, nextDomain, id, nextID, cname, nextCNAME types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("domain"), &domain)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("domain"), &nextDomain)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("id"), &nextID)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("cname"), &cname)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("cname"), &nextCNAME)...)
	if resp.Diagnostics.HasError() || !domain.Equal(nextDomain) || !id.Equal(nextID) || !cname.Equal(nextCNAME) || domain.ValueString() == "" {
		resp.Diagnostics.AddError("CDN identity changed", "A certificate update must retain the domain ID and CNAME.")
		return
	}
	if err := r.updateCertificate(ctx, domain.ValueString(), cname.ValueString(), oldBinding, newBinding); err != nil {
		resp.Diagnostics.AddError("Unable to update CDN certificate in place", err.Error())
		return
	}
	// Cloud Control remains the state reader. Wait for its projection too,
	// retaining the original state on any failure so dependent retirement stops.
	for attempt := 0; attempt < r.maxAttempts(); attempt++ {
		read := resource.ReadResponse{State: req.State}
		r.Resource.Read(ctx, resource.ReadRequest{State: req.State}, &read)
		if read.Diagnostics.HasError() || read.State.Raw.IsNull() {
			resp.Diagnostics.AddError("Unable to refresh updated CDN certificate", "Cloud Control did not confirm the existing domain; keep both certificates and refresh again.")
			return
		}
		var currentHTTPS types.Object
		var currentID, currentCNAME types.String
		resp.Diagnostics.Append(read.State.GetAttribute(ctx, path.Root("https"), &currentHTTPS)...)
		resp.Diagnostics.Append(read.State.GetAttribute(ctx, path.Root("id"), &currentID)...)
		resp.Diagnostics.Append(read.State.GetAttribute(ctx, path.Root("cname"), &currentCNAME)...)
		if resp.Diagnostics.HasError() || !currentID.Equal(id) || !currentCNAME.Equal(cname) {
			resp.Diagnostics.AddError("Updated CDN identity could not be confirmed", "The domain ID/CNAME must remain unchanged; retain both certificates.")
			return
		}
		if current, err := httpsBinding(currentHTTPS); err == nil && current == newBinding {
			state, err := hydrateHTTPSPlan(ctx, req.Plan, read.State)
			if err != nil {
				resp.Diagnostics.AddError("Unable to record CDN certificate update", err.Error())
				return
			}
			resp.State = state
			return
		}
		if err := r.pause(ctx); err != nil {
			break
		}
	}
	resp.Diagnostics.AddError("CDN certificate projection did not converge", "Keep both certificates; the existing domain was not recreated. Refresh before retrying.")
}

func (r *domainHTTPSResource) updateCertificate(ctx context.Context, domain, cname string, old, target certificateBinding) error {
	before, err := r.api.Observe(ctx, domain)
	if err != nil {
		return err
	}
	if before.CNAME != cname || before.Status != "online" || (before.Binding != old && before.Binding != target) {
		return errors.New("live CDN identity/binding differs or another configuration is in progress; no update sent")
	}
	if err := r.api.Verify(ctx, domain, target); err != nil {
		return err
	}
	if before.Binding != target {
		payload, err := httpsCertificatePayload(before, target)
		if err != nil {
			return err
		}
		if err := r.api.Update(ctx, domain, payload); err != nil {
			return err
		}
	}
	consecutive := 0
	for attempt := 0; attempt < r.maxAttempts(); attempt++ {
		current, err := r.api.Observe(ctx, domain)
		if err == nil {
			if current.Domain != before.Domain || current.CNAME != before.CNAME || current.Project != before.Project || current.SettingsHash != before.SettingsHash || current.OtherHash != before.OtherHash {
				return errors.New("CDN settings changed during certificate update; no rollback or domain deletion was attempted; retain both certificates")
			}
			if current.Binding != old && current.Binding != target {
				return errors.New("a foreign certificate binding was observed; retain both certificates and refresh before retrying")
			}
			if current.Binding == target && current.Status == "online" {
				consecutive++
				if consecutive >= 2 {
					return r.api.Verify(ctx, domain, target)
				}
			} else {
				consecutive = 0
			}
		} else {
			consecutive = 0
		}
		if err := r.pause(ctx); err != nil {
			return err
		}
	}
	return errors.New("CDN certificate update did not converge; retain both certificates and refresh before retrying")
}

func hydrateHTTPSPlan(ctx context.Context, plan tfsdk.Plan, observed tfsdk.State) (tfsdk.State, error) {
	raw, err := tftypes.Transform(plan.Raw, func(p *tftypes.AttributePath, value tftypes.Value) (tftypes.Value, error) {
		if value.IsKnown() && !value.IsFullyKnown() {
			return value, nil
		}
		found, remaining, err := tftypes.WalkAttributePath(observed.Raw, p)
		if err != nil || len(remaining.Steps()) != 0 {
			return value, fmt.Errorf("unable to read updated computed attribute")
		}
		actual := found.(tftypes.Value)
		if value.IsKnown() {
			if !value.Equal(actual) {
				return value, errors.New("observed CDN configuration differs from the reviewed plan; refresh before retrying")
			}
			return value, nil
		}
		return actual, nil
	})
	if err != nil {
		return tfsdk.State{}, err
	}
	if !raw.IsFullyKnown() {
		return tfsdk.State{}, errors.New("updated CDN computed values remain unknown")
	}
	return tfsdk.State{Schema: plan.Schema, Raw: raw}, nil
}

var _ resource.ResourceWithConfigure = (*domainHTTPSResource)(nil)
var _ resource.ResourceWithModifyPlan = (*domainHTTPSResource)(nil)
var _ resource.ResourceWithImportState = (*domainHTTPSResource)(nil)
var _ resource.ResourceWithConfigValidators = (*domainHTTPSResource)(nil)
