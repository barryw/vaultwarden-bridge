package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &SecretDataSource{}

type SecretDataSource struct {
	client *VaultwardenClient
}

type SecretDataSourceModel struct {
	Key       types.String `tfsdk:"key"`
	Value     types.String `tfsdk:"value"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func NewSecretDataSource() datasource.DataSource {
	return &SecretDataSource{}
}

func (d *SecretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a secret from Vaultwarden Bridge.",
		Attributes: map[string]schema.Attribute{
			"key": schema.StringAttribute{
				MarkdownDescription: "The secret key/name to retrieve.",
				Required:            true,
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "The secret value.",
				Computed:            true,
				Sensitive:           true,
			},
			"updated_at": schema.StringAttribute{
				MarkdownDescription: "When the secret was last modified.",
				Computed:            true,
			},
		},
	}
}

func (d *SecretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*VaultwardenClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected type", fmt.Sprintf("Expected *VaultwardenClient, got %T", req.ProviderData))
		return
	}
	d.client = client
}

type secretResponse struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SecretDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/api/v1/secret/%s", d.client.Address, data.Key.ValueString())
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		resp.Diagnostics.AddError("Request error", err.Error())
		return
	}
	httpReq.Header.Set("Authorization", "Bearer "+d.client.ApiKey)

	httpResp, err := d.client.HTTP.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("HTTP error", err.Error())
		return
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		resp.Diagnostics.AddError("Read error", err.Error())
		return
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		var secret secretResponse
		if err := json.Unmarshal(body, &secret); err != nil {
			resp.Diagnostics.AddError("JSON parse error", err.Error())
			return
		}
		data.Value = types.StringValue(secret.Value)
		data.UpdatedAt = types.StringValue(secret.UpdatedAt)
	case http.StatusForbidden:
		var errResp errorResponse
		json.Unmarshal(body, &errResp)
		resp.Diagnostics.AddError("Access denied", fmt.Sprintf("Machine key does not have access to '%s': %s", data.Key.ValueString(), errResp.Error))
		return
	case http.StatusNotFound:
		resp.Diagnostics.AddError("Secret not found", fmt.Sprintf("No secret found with key '%s'", data.Key.ValueString()))
		return
	case http.StatusUnauthorized:
		resp.Diagnostics.AddError("Unauthorized", "Invalid or expired API key")
		return
	default:
		resp.Diagnostics.AddError("Unexpected error", fmt.Sprintf("Status %d: %s", httpResp.StatusCode, string(body)))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
