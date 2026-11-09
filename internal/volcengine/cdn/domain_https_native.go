// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	sdkcdn "github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/custom"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type certificateBinding struct{ ID, Source string }

type httpsObservation struct {
	Domain, Project, CNAME, Status string
	Binding                        certificateBinding
	HTTPS                          map[string]interface{}
	SettingsHash, OtherHash        [32]byte
}

type httpsCertificateAPI interface {
	Observe(context.Context, string) (httpsObservation, error)
	Verify(context.Context, string, certificateBinding) error
	Update(context.Context, string, map[string]interface{}) error
}

type nativeHTTPSClient struct{ client *sdkcdn.CDN }

func newNativeHTTPSClient(config *volcengine.Config) (httpsCertificateAPI, error) {
	// Reuse the configured credential chain (including profile/AssumeRole),
	// transport and proxy policy, but never the Cloud Control service endpoint.
	config = config.Copy()
	config.Endpoint = nil
	var transport *http.Transport
	var proxy func(*http.Request) (*url.URL, error)
	if config.HTTPClient != nil {
		clientCopy := *config.HTTPClient
		if original, ok := clientCopy.Transport.(*http.Transport); ok {
			transport = original.Clone()
			proxy = transport.Proxy
			clientCopy.Transport = transport
		}
		config.HTTPClient = &clientCopy
	}
	config.WithMaxRetries(0).WithForceJsonNumberDecode(func(context.Context, custom.RequestInfo) bool { return true })
	sess, err := session.NewSession(config)
	if err != nil {
		return nil, errors.New("unable to configure native CDN client")
	}
	client := sdkcdn.New(sess)
	// The SDK installs its static proxy during ClientConfig. Restore the
	// provider's no_proxy/include-domain selector on our private transport.
	if transport != nil {
		transport.Proxy = proxy
	}
	return &nativeHTTPSClient{client: client}, nil
}

func bindingValid(binding certificateBinding) bool {
	return binding.ID != "" && strings.TrimSpace(binding.ID) == binding.ID &&
		(binding.Source == "volc_cert_center" || binding.Source == "cdn_cert_hosting")
}

func pruneHTTPSNulls(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, value := range typed {
			if value != nil {
				out[key] = pruneHTTPSNulls(value)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for index, value := range typed {
			out[index] = pruneHTTPSNulls(value)
		}
		return out
	default:
		return value
	}
}

func canonicalJSONSet(items []interface{}) {
	sort.Slice(items, func(i, j int) bool {
		left, _ := json.Marshal(items[i])
		right, _ := json.Marshal(items[j])
		return bytes.Compare(left, right) < 0
	})
}

func normalizeHTTPSSettings(settings map[string]interface{}) map[string]interface{} {
	normalized := pruneHTTPSNulls(settings).(map[string]interface{})
	if versions, ok := normalized["TlsVersion"].([]interface{}); ok {
		canonicalJSONSet(versions)
	}
	if check, ok := normalized["CertCheck"].(map[string]interface{}); ok {
		if certificates, ok := check["CertInfoList"].([]interface{}); ok {
			canonicalJSONSet(certificates)
		}
	}
	// Route/cache/header arrays elsewhere remain ordered: their priority is
	// semantically meaningful and must not be hidden by generic sorting.
	return normalized
}

func normalizeOtherCDNConfig(config map[string]interface{}) map[string]interface{} {
	normalized := pruneHTTPSNulls(config).(map[string]interface{})
	if origins, ok := normalized["Origin"].([]interface{}); ok {
		for _, origin := range origins {
			if object, ok := origin.(map[string]interface{}); ok {
				if action, ok := object["OriginAction"].(map[string]interface{}); ok {
					if lines, ok := action["OriginLines"].([]interface{}); ok {
						canonicalJSONSet(lines)
					}
				}
			}
		}
	}
	return normalized
}

func decodeHTTPSObservation(raw map[string]interface{}, domain string) (httpsObservation, error) {
	var out httpsObservation
	metadata, ok := raw["ResponseMetadata"].(map[string]interface{})
	if !ok || metadata["Error"] != nil || metadata["Action"] != "DescribeCdnConfig" {
		return out, errors.New("DescribeCdnConfig returned missing or error metadata")
	}
	result, ok := raw["Result"].(map[string]interface{})
	if !ok {
		return out, errors.New("DescribeCdnConfig returned no result")
	}
	config, ok := result["DomainConfig"].(map[string]interface{})
	if !ok || config["Domain"] != domain {
		return out, errors.New("DescribeCdnConfig returned a different domain")
	}
	project, _ := config["Project"].(string)
	cname, _ := config["Cname"].(string)
	status, _ := config["Status"].(string)
	if project == "" || cname == "" || (status != "online" && status != "configuring") {
		return out, errors.New("CDN identity is incomplete or the domain is not online/configuring")
	}
	https, ok := config["HTTPS"].(map[string]interface{})
	if !ok || https["Switch"] != true {
		return out, errors.New("certificate rotation requires existing enabled HTTPS")
	}
	if list := https["CertInfoList"]; list != nil {
		items, ok := list.([]interface{})
		if !ok || len(items) != 0 {
			return out, errors.New("dual-certificate HTTPS is outside the certificate-only update")
		}
	}
	cert, ok := https["CertInfo"].(map[string]interface{})
	if !ok {
		return out, errors.New("CDN has no single certificate binding")
	}
	binding := certificateBinding{}
	binding.ID, _ = cert["CertId"].(string)
	binding.Source, _ = cert["Source"].(string)
	if !bindingValid(binding) || cert["EncryType"] != "inter_cert" {
		return out, errors.New("CDN certificate binding is not a supported ordinary certificate")
	}
	if material := cert["Certificate"]; material != nil {
		object, ok := material.(map[string]interface{})
		if !ok {
			return out, errors.New("CDN certificate material has an unsupported shape")
		}
		for _, value := range object {
			if value != nil && value != "" {
				return out, errors.New("inline certificate material is outside the certificate-only update")
			}
		}
	}
	if keyless := https["Keyless"]; keyless != nil {
		object, ok := keyless.(map[string]interface{})
		if !ok || object["Switch"] != false {
			return out, errors.New("keyless HTTPS is outside the certificate-only update")
		}
		for key, value := range object {
			if key != "Switch" && value != nil && value != "" {
				return out, errors.New("keyless HTTPS contains unsupported settings")
			}
		}
	}
	settings := make(map[string]interface{}, len(https))
	for key, value := range https {
		if key != "CertInfo" && key != "CertInfoList" {
			settings[key] = value
		}
	}
	encoded, err := json.Marshal(normalizeHTTPSSettings(settings))
	if err != nil {
		return out, errors.New("unable to encode HTTPS settings")
	}
	otherConfig := make(map[string]interface{}, len(config))
	for key, value := range config {
		switch key {
		case "HTTPS", "CreateTime", "CreatedTime", "UpdateTime", "UpdatedTime",
			"Status", "LockStatus", "DomainLock", "IsConflictDomain", "Cname",
			"BackupOrigin", "PrimaryOrigin", "CacheShared", "CacheSharedTargetHost":
			// Operational/derived fields declared read-only by the CDN Cloud
			// Control schema, plus native API timestamp aliases. Domain/CNAME
			// identity and readiness are checked independently by the waiter.
			continue
		default:
			otherConfig[key] = value
		}
	}
	// FeatureConfig and ModuleLockConfig are result-level service state, not
	// the desired domain configuration. They can change during deployment and
	// must not cause a landed certificate update to fail the drift check.
	otherEncoded, err := json.Marshal(normalizeOtherCDNConfig(otherConfig))
	if err != nil {
		return out, errors.New("unable to encode other CDN configuration")
	}
	return httpsObservation{Domain: domain, Project: project, CNAME: cname, Status: status,
		Binding: binding, HTTPS: https, SettingsHash: sha256.Sum256(encoded), OtherHash: sha256.Sum256(otherEncoded)}, nil
}

func httpsCertificatePayload(before httpsObservation, target certificateBinding) (map[string]interface{}, error) {
	if !bindingValid(target) {
		return nil, errors.New("invalid target certificate binding")
	}
	https := pruneHTTPSNulls(before.HTTPS).(map[string]interface{})
	delete(https, "CertInfoList")
	https["CertInfo"] = map[string]interface{}{"CertId": target.ID, "Source": target.Source, "EncryType": "inter_cert"}
	// Keyless is returned by the service but is not modeled by this SDK. Only
	// its explicitly disabled shape is supported; retain it unchanged in JSON.
	keyless, hasKeyless := https["Keyless"]
	delete(https, "Keyless")
	encoded, err := json.Marshal(https)
	if err != nil {
		return nil, errors.New("unable to encode HTTPS update")
	}
	var typed sdkcdn.HTTPSForUpdateCdnConfigInput
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&typed); err != nil {
		return nil, errors.New("live HTTPS contains fields not representable by the native update API")
	}
	if hasKeyless {
		https["Keyless"] = keyless
	}
	return map[string]interface{}{"Domain": before.Domain, "HTTPS": https}, nil
}

func (c *nativeHTTPSClient) Observe(ctx context.Context, domain string) (httpsObservation, error) {
	payload := map[string]interface{}{"Domain": domain}
	out, err := c.client.DescribeCdnConfigCommonWithContext(ctx, &payload)
	if err != nil || out == nil {
		return httpsObservation{}, errors.New("native CDN configuration read failed")
	}
	return decodeHTTPSObservation(*out, domain)
}

func (c *nativeHTTPSClient) Verify(ctx context.Context, domain string, binding certificateBinding) error {
	out, err := c.client.ListCertInfoWithContext(ctx, (&sdkcdn.ListCertInfoInput{}).
		SetSource(binding.Source).SetCertId(binding.ID).SetPageNum(1).SetPageSize(2))
	if err != nil || out == nil || out.Metadata == nil || out.Metadata.Error != nil || out.Total == nil || *out.Total != 1 || len(out.CertInfo) != 1 || out.CertInfo[0] == nil {
		return errors.New("target certificate could not be identified in CDN inventory")
	}
	cert := out.CertInfo[0]
	if volcengine.StringValue(cert.CertId) != binding.ID || volcengine.StringValue(cert.Source) != binding.Source ||
		volcengine.StringValue(cert.CertType) != "server_cert" || volcengine.StringValue(cert.EncryType) != "inter_cert" {
		return errors.New("target certificate identity or type does not match")
	}
	now := time.Now().Unix()
	if cert.EffectiveTime == nil || cert.ExpireTime == nil || *cert.EffectiveTime > now || *cert.ExpireTime <= now ||
		(volcengine.StringValue(cert.Status) != "running" && volcengine.StringValue(cert.Status) != "expiring_soon") {
		return errors.New("target certificate is not currently valid")
	}
	names := strings.Split(volcengine.StringValue(cert.DnsName), ",")
	for index := range names {
		names[index] = strings.TrimSpace(names[index])
	}
	if (&x509.Certificate{DNSNames: names}).VerifyHostname(domain) != nil {
		return errors.New("target certificate does not cover the CDN hostname")
	}
	return nil
}

func (c *nativeHTTPSClient) Update(ctx context.Context, _ string, payload map[string]interface{}) error {
	out, err := c.client.UpdateCdnConfigCommonWithContext(ctx, &payload)
	if err != nil {
		return fmt.Errorf("native CDN certificate update failed; retain both certificates: %w", err)
	}
	if out == nil {
		return errors.New("native CDN certificate update returned no response; retain both certificates")
	}
	metadata, ok := (*out)["ResponseMetadata"].(map[string]interface{})
	if !ok || metadata["Action"] != "UpdateCdnConfig" || metadata["Error"] != nil {
		return errors.New("native CDN certificate update returned an ambiguous response; retain both certificates")
	}
	return nil
}
