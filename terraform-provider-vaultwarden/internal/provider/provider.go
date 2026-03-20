package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &VaultwardenProvider{}

type VaultwardenProvider struct {
	version string
}

type VaultwardenProviderModel struct {
	Address types.String `tfsdk:"address"`
	ApiKey  types.String `tfsdk:"api_key"`
}

type VaultwardenClient struct {
	Address string
	ApiKey  string
	HTTP    *http.Client
	Version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &VaultwardenProvider{version: version}
	}
}

func (p *VaultwardenProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vaultwarden"
	resp.Version = p.version
}

func (p *VaultwardenProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Vaultwarden Bridge provider retrieves secrets from a Vaultwarden Bridge instance.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				MarkdownDescription: "Bridge server URL. Can also be set via VAULTWARDEN_BRIDGE_ADDRESS env var.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Machine API key. Can also be set via VAULTWARDEN_BRIDGE_API_KEY env var.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *VaultwardenProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data VaultwardenProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	address := os.Getenv("VAULTWARDEN_BRIDGE_ADDRESS")
	if !data.Address.IsNull() {
		address = data.Address.ValueString()
	}
	if address == "" {
		resp.Diagnostics.AddError("Missing address", "Set address in provider config or VAULTWARDEN_BRIDGE_ADDRESS env var")
		return
	}

	apiKey := os.Getenv("VAULTWARDEN_BRIDGE_API_KEY")
	if !data.ApiKey.IsNull() {
		apiKey = data.ApiKey.ValueString()
	}
	if apiKey == "" {
		resp.Diagnostics.AddError("Missing api_key", "Set api_key in provider config or VAULTWARDEN_BRIDGE_API_KEY env var")
		return
	}

	client := &VaultwardenClient{
		Address: address,
		ApiKey:  apiKey,
		Version: p.version,
		HTTP: &http.Client{
			Transport: &userAgentTransport{
				underlying: http.DefaultTransport,
				userAgent:  fmt.Sprintf("terraform-provider-vaultwarden/%s", p.version),
			},
		},
	}

	resp.DataSourceData = client
}

func (p *VaultwardenProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *VaultwardenProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

type userAgentTransport struct {
	underlying http.RoundTripper
	userAgent  string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.underlying.RoundTrip(req)
}
