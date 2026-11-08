// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cdn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	sdkcdn "github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/custom"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const nativeHTTPSTestDomain = "legacy.example.com"

func nativeHTTPSFixture(id string) map[string]interface{} {
	return map[string]interface{}{
		"ResponseMetadata": map[string]interface{}{"Action": "DescribeCdnConfig"},
		"Result": map[string]interface{}{
			"FeatureConfig":    map[string]interface{}{"Feature": true},
			"ModuleLockConfig": map[string]interface{}{"Lock": false},
			"DomainConfig": map[string]interface{}{
				"Domain": nativeHTTPSTestDomain, "Cname": "legacy.cdn.example.net", "Project": "fixture", "Status": "online", "UpdateTime": 1,
				"OriginRewrite":  map[string]interface{}{"Switch": true, "Rules": []interface{}{"keep-route"}},
				"Cache":          []interface{}{map[string]interface{}{"Rule": "keep-cache"}},
				"ResponseHeader": []interface{}{map[string]interface{}{"Header": "keep-header"}},
				"HTTPS": map[string]interface{}{
					"Switch": true, "HTTP2": true, "DisableHttp": false, "OCSP": true,
					"TlsVersion":     []interface{}{"tlsv1.2", "tlsv1.3"},
					"ForcedRedirect": map[string]interface{}{"EnableForcedRedirect": true, "StatusCode": "301"},
					"Hsts":           map[string]interface{}{"Switch": false, "Subdomain": nil, "Ttl": json.Number("0")},
					"CertCheck":      nil, "Keyless": nil, "CertInfoList": nil,
					"CertInfo": map[string]interface{}{"CertId": id, "Source": "volc_cert_center", "EncryType": "inter_cert", "Certificate": nil, "EffectiveTime": 1, "ExpireTime": 2},
				},
			},
		},
	}
}

func nativeHTTPSConfig(raw map[string]interface{}) map[string]interface{} {
	return raw["Result"].(map[string]interface{})["DomainConfig"].(map[string]interface{})
}
func nativeHTTPSSettings(raw map[string]interface{}) map[string]interface{} {
	return nativeHTTPSConfig(raw)["HTTPS"].(map[string]interface{})
}
func nativeHTTPSObserved(t *testing.T, id string) httpsObservation {
	t.Helper()
	observation, err := decodeHTTPSObservation(nativeHTTPSFixture(id), nativeHTTPSTestDomain)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestNativeHTTPSPayloadPreservesExistingSettings(t *testing.T) {
	before := nativeHTTPSObserved(t, "old-cert")
	payload, err := httpsCertificatePayload(before, certificateBinding{"new-cert", "volc_cert_center"})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 2 || payload["Domain"] != nativeHTTPSTestDomain {
		t.Fatalf("update must contain only Domain and HTTPS: %#v", payload)
	}
	https := payload["HTTPS"].(map[string]interface{})
	if !reflect.DeepEqual(https["CertInfo"], map[string]interface{}{"CertId": "new-cert", "Source": "volc_cert_center", "EncryType": "inter_cert"}) {
		t.Fatal("target binding differs")
	}
	delete(https, "CertInfo")
	prior := pruneHTTPSNulls(before.HTTPS).(map[string]interface{})
	delete(prior, "CertInfo")
	delete(prior, "CertInfoList")
	if !reflect.DeepEqual(https, prior) || before.Binding.ID != "old-cert" {
		t.Fatal("HTTPS settings changed or the observed snapshot was mutated")
	}
	for _, key := range []string{"OriginRewrite", "Cache", "ResponseHeader", "DNS", "Cname"} {
		if _, exists := payload[key]; exists {
			t.Fatalf("unrelated module %s was sent", key)
		}
	}
}

func TestNativeHTTPSRejectsUnsupportedShapes(t *testing.T) {
	cases := map[string]func(map[string]interface{}){
		"wrong identity": func(raw map[string]interface{}) { nativeHTTPSConfig(raw)["Domain"] = "foreign.example.com" },
		"offline":        func(raw map[string]interface{}) { nativeHTTPSConfig(raw)["Status"] = "offline" },
		"disabled":       func(raw map[string]interface{}) { nativeHTTPSSettings(raw)["Switch"] = false },
		"dual": func(raw map[string]interface{}) {
			nativeHTTPSSettings(raw)["CertInfoList"] = []interface{}{map[string]interface{}{"CertId": "other"}}
		},
		"keyless": func(raw map[string]interface{}) {
			nativeHTTPSSettings(raw)["Keyless"] = map[string]interface{}{"Switch": true}
		},
		"inline": func(raw map[string]interface{}) {
			nativeHTTPSSettings(raw)["CertInfo"].(map[string]interface{})["Certificate"] = map[string]interface{}{"PrivateKey": "DO-NOT-LOG"}
		},
		"SM": func(raw map[string]interface{}) {
			nativeHTTPSSettings(raw)["CertInfo"].(map[string]interface{})["EncryType"] = "sm_cert"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw := nativeHTTPSFixture("old-cert")
			change(raw)
			_, err := decodeHTTPSObservation(raw, nativeHTTPSTestDomain)
			if err == nil || strings.Contains(err.Error(), "DO-NOT-LOG") {
				t.Fatalf("unsafe shape accepted or material logged: %v", err)
			}
		})
	}
	for _, key := range []string{"UnknownHTTPSField", "unknownhttpsfield"} {
		raw := nativeHTTPSFixture("old-cert")
		nativeHTTPSSettings(raw)[key] = true
		before, err := decodeHTTPSObservation(raw, nativeHTTPSTestDomain)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := httpsCertificatePayload(before, certificateBinding{"new-cert", "volc_cert_center"}); err == nil {
			t.Fatal("unrepresentable HTTPS field was silently discarded")
		}
	}
}

func TestNativeHTTPSSetOrderDoesNotHideOrderedPolicyDrift(t *testing.T) {
	first := nativeHTTPSFixture("old-cert")
	second := nativeHTTPSFixture("new-cert")
	nativeHTTPSSettings(second)["TlsVersion"] = []interface{}{"tlsv1.3", "tlsv1.2"}
	before, err := decodeHTTPSObservation(first, nativeHTTPSTestDomain)
	if err != nil {
		t.Fatal(err)
	}
	after, err := decodeHTTPSObservation(second, nativeHTTPSTestDomain)
	if err != nil || before.SettingsHash != after.SettingsHash || before.OtherHash != after.OtherHash {
		t.Fatalf("TLS set reorder became drift: %v", err)
	}
	nativeHTTPSConfig(second)["OriginRewrite"] = map[string]interface{}{"Switch": true, "Rules": []interface{}{"changed-route"}}
	after, err = decodeHTTPSObservation(second, nativeHTTPSTestDomain)
	if err != nil || before.OtherHash == after.OtherHash {
		t.Fatalf("real route drift was hidden: %v", err)
	}
}

func TestNativeHTTPSActualSDKProtocol(t *testing.T) {
	var updateCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]interface{}
		if json.NewDecoder(req.Body).Decode(&body) != nil || req.Method != http.MethodPost {
			t.Error("invalid request")
			return
		}
		action := req.URL.Query().Get("Action")
		var result interface{}
		switch action {
		case "DescribeCdnConfig":
			if !reflect.DeepEqual(body, map[string]interface{}{"Domain": nativeHTTPSTestDomain}) {
				t.Error("unexpected Describe request")
			}
			result = nativeHTTPSFixture("old-cert")["Result"]
		case "ListCertInfo":
			if body["CertId"] != "new-cert" || body["Source"] != "volc_cert_center" {
				t.Error("wrong target inventory")
			}
			result = map[string]interface{}{"Total": 1, "CertInfo": []interface{}{map[string]interface{}{
				"CertId": "new-cert", "Source": "volc_cert_center", "CertType": "server_cert", "EncryType": "inter_cert", "Status": "running", "DnsName": "*.example.com", "EffectiveTime": time.Now().Unix() - 60, "ExpireTime": time.Now().Unix() + 3600,
			}}}
		case "UpdateCdnConfig":
			updateCount++
			if len(body) != 2 || body["Domain"] != nativeHTTPSTestDomain || body["HTTPS"].(map[string]interface{})["CertInfo"].(map[string]interface{})["CertId"] != "new-cert" {
				t.Error("unexpected native update request")
			}
			result = map[string]interface{}{}
		default:
			t.Errorf("unexpected write/action %s", action)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ResponseMetadata": map[string]interface{}{"Action": action}, "Result": result})
	}))
	defer server.Close()
	config := volcengine.NewConfig().WithEndpoint(server.URL).WithDisableSSL(true).WithRegion("cn-beijing").WithMaxRetries(0).
		WithCredentials(credentials.NewStaticCredentials("fixture", "fixture", "")).WithForceJsonNumberDecode(func(context.Context, custom.RequestInfo) bool { return true })
	client := &nativeHTTPSClient{client: sdkcdn.New(session.New(config))}
	before, err := client.Observe(context.Background(), nativeHTTPSTestDomain)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Verify(context.Background(), nativeHTTPSTestDomain, certificateBinding{"new-cert", "volc_cert_center"}); err != nil {
		t.Fatal(err)
	}
	payload, err := httpsCertificatePayload(before, certificateBinding{"new-cert", "volc_cert_center"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Update(context.Background(), nativeHTTPSTestDomain, payload); err != nil || updateCount != 1 {
		t.Fatalf("native update: %v, calls=%d", err, updateCount)
	}
}

func TestNativeHTTPSUpdateDoesNotRetryAmbiguousFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.URL.Query().Get("Action") != "UpdateCdnConfig" {
			t.Errorf("unexpected request action")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ResponseMetadata":{"Action":"UpdateCdnConfig","Error":{"Code":"InternalError","Message":"temporary"}}}`))
	}))
	defer server.Close()
	config := volcengine.NewConfig().WithEndpoint(server.URL).WithDisableSSL(true).WithRegion("cn-beijing").WithMaxRetries(0).
		WithCredentials(credentials.NewStaticCredentials("fixture", "fixture", ""))
	client := &nativeHTTPSClient{client: sdkcdn.New(session.New(config))}
	err := client.Update(context.Background(), nativeHTTPSTestDomain, map[string]interface{}{"Domain": nativeHTTPSTestDomain, "HTTPS": map[string]interface{}{}})
	if err == nil || calls != 1 {
		t.Fatalf("ambiguous native update accepted or repeated: err=%v calls=%d", err, calls)
	}
}

func TestNativeHTTPSClientReusesCredentialsWithoutCloudControlEndpoint(t *testing.T) {
	original := volcengine.NewConfig().WithEndpoint("https://cloudcontrol.example.com").WithRegion("cn-beijing").WithCredentials(credentials.NewStaticCredentials("fixture", "fixture", "fixture-session"))
	api, err := newNativeHTTPSClient(original)
	if err != nil {
		t.Fatal(err)
	}
	client := api.(*nativeHTTPSClient).client
	if original.Endpoint == nil || *original.Endpoint != "https://cloudcontrol.example.com" || strings.Contains(client.ClientInfo.Endpoint, "cloudcontrol.example.com") ||
		client.Config.Credentials != original.Credentials || client.MaxRetries() != 0 {
		t.Fatal("native client changed configured identity or retained the Cloud Control endpoint/retries")
	}
}

func TestNativeHTTPSClientPreservesDynamicProxyPolicy(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		if request.URL.Hostname() == "direct.example.com" {
			return nil, nil
		}
		return proxyURL, nil
	}
	originalClient := &http.Client{Transport: transport}
	config := volcengine.NewConfig().WithRegion("cn-beijing").WithEndpoint("https://cloudcontrol.example.com").
		WithCredentials(credentials.NewStaticCredentials("fixture", "fixture", "")).WithHTTPClient(originalClient).
		WithHTTPProxy(proxyURL.String()).WithHTTPSProxy(proxyURL.String())
	api, err := newNativeHTTPSClient(config)
	if err != nil {
		t.Fatal(err)
	}
	nativeClient := api.(*nativeHTTPSClient).client.Config.HTTPClient
	nativeTransport := nativeClient.Transport.(*http.Transport)
	if nativeClient == originalClient || nativeTransport == transport {
		t.Fatal("native CDN client shares a mutable HTTP client/transport")
	}
	for _, candidate := range []*http.Transport{transport, nativeTransport} {
		for host, wantProxy := range map[string]bool{"direct.example.com": false, "proxied.example.com": true} {
			request, _ := http.NewRequest(http.MethodGet, "https://"+host, nil)
			actual, err := candidate.Proxy(request)
			if err != nil || (actual != nil) != wantProxy {
				t.Fatalf("proxy selector changed for %s: %v %v", host, actual, err)
			}
		}
	}
}

type nativeHTTPSTestAPI struct {
	current   httpsObservation
	reads     []httpsObservation
	updates   int
	writeErr  error
	verifyErr error
}

func (f *nativeHTTPSTestAPI) Observe(context.Context, string) (httpsObservation, error) {
	if len(f.reads) > 0 {
		f.current, f.reads = f.reads[0], f.reads[1:]
	}
	return f.current, nil
}
func (f *nativeHTTPSTestAPI) Verify(context.Context, string, certificateBinding) error {
	return f.verifyErr
}
func (f *nativeHTTPSTestAPI) Update(context.Context, string, map[string]interface{}) error {
	f.updates++
	return f.writeErr
}

func TestNativeHTTPSConvergenceAndRecovery(t *testing.T) {
	before := nativeHTTPSObserved(t, "old-cert")
	target := nativeHTTPSObserved(t, "new-cert")
	configuringOld, configuringNew := before, target
	configuringOld.Status, configuringNew.Status = "configuring", "configuring"
	foreign := target
	foreign.SettingsHash[0] ^= 1
	for _, tc := range []struct {
		name     string
		reads    []httpsObservation
		writeErr error
		wantErr  bool
		updates  int
	}{
		{"asynchronous", []httpsObservation{before, configuringOld, configuringNew, target, target}, nil, false, 1},
		{"already landed", []httpsObservation{target, target, target}, nil, false, 0},
		{"never landed", []httpsObservation{before, before, before, before, before}, nil, true, 1},
		{"write failed", []httpsObservation{before}, errors.New("response lost"), true, 1},
		{"foreign settings", []httpsObservation{before, foreign}, nil, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &nativeHTTPSTestAPI{current: before, reads: tc.reads, writeErr: tc.writeErr}
			r := &domainHTTPSResource{api: api, wait: func(context.Context) error { return nil }, attempts: 6}
			err := r.updateCertificate(context.Background(), before.Domain, before.CNAME, before.Binding, target.Binding)
			if (err != nil) != tc.wantErr || api.updates != tc.updates {
				t.Fatalf("result=%v updates=%d", err, api.updates)
			}
		})
	}
}
