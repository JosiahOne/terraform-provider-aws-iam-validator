package provider

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	awstypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &ValidatePolicyDataSource{}

// ValidatePolicyDataSource implements datasource.DataSource for AWS IAM policy validation.
type ValidatePolicyDataSource struct{}

func NewValidatePolicyDataSource() datasource.DataSource {
	return &ValidatePolicyDataSource{}
}

func (d *ValidatePolicyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "aws-iam-validator"
}

func (d *ValidatePolicyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Validates an AWS IAM policy JSON string using the AWS Access Analyzer ValidatePolicy API.",
		Attributes: map[string]schema.Attribute{
			"policy_json": schema.StringAttribute{
				Description: "IAM policy JSON string to validate.",
				Required:    true,
			},
			"findings": schema.ListAttribute{
				Description: "List of findings from the AWS ValidatePolicy API.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (d *ValidatePolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data struct {
		PolicyJSON types.String `tfsdk:"policy_json"`
		Findings   []string     `tfsdk:"findings"`
	}

	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		resp.Diagnostics.AddError("AWS config error", err.Error())
		return
	}

	client := accessanalyzer.NewFromConfig(cfg)
	policyDoc := data.PolicyJSON.ValueString()
	input := &accessanalyzer.ValidatePolicyInput{
		PolicyDocument: &policyDoc,
		PolicyType:     awstypes.PolicyType("IDENTITY_POLICY"),
	}

	result, err := client.ValidatePolicy(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("ValidatePolicy error", err.Error())
		return
	}

	findings := []string{}
	for _, finding := range result.Findings {
		msg, _ := json.Marshal(finding)
		findings = append(findings, string(msg))
	}

	data.Findings = findings
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}
