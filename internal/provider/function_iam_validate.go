// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	awstypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var validatePolicyReturnAttrTypes = map[string]attr.Type{
	"errors": types.ListType{ElemType: types.StringType},
}

var _ function.Function = &ValidatePolicyFunction{}

type ValidatePolicyFunction struct{}

func NewValidatePolicyFunction() function.Function {
	return &ValidatePolicyFunction{}
}

func (f *ValidatePolicyFunction) Metadata(ctx context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "validate_policy"
}

func (f *ValidatePolicyFunction) Definition(ctx context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	tflog.Info(ctx, "ValidatePolicyFunction.GetDefinition")

	resp.Definition = function.Definition{
		Summary:     "Validate an AWS IAM policy JSON string using the AWS Access Analyzer ValidatePolicy API.",
		Description: "Given an IAM policy JSON string, calls AWS ValidatePolicy and returns a list of validation errors.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "policy_json",
				Description: "IAM policy JSON string to validate.",
			},
		},
		Return: function.ObjectReturn{
			AttributeTypes: validatePolicyReturnAttrTypes,
		},
	}
}

func (f *ValidatePolicyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {

	tflog.Info(ctx, "ValidatePolicyFunction.Run")
	// Get arguments as attr.Value
	var policyJSONVal string
	resp.Error = req.Arguments.GetArgument(ctx, 0, &policyJSONVal)
	if resp.Error != nil {
		tflog.Error(ctx, fmt.Sprintf("ValidatePolicyFunction error: %s\n\n", resp.Error.Error()))
		return
	}

	var policyType string = "IDENTITY_POLICY"
	tflog.Info(ctx, "ValidatePolicyFunction.LoadingConfig")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("failed to load AWS config: %s", err.Error()))
		resp.Error = function.NewFuncError(fmt.Sprintf("AWS config error: %s", err.Error()))
		return
	}

	client := accessanalyzer.NewFromConfig(cfg)
	input := &accessanalyzer.ValidatePolicyInput{
		PolicyDocument: &policyJSONVal,
		PolicyType:     awstypes.PolicyType(policyType),
	}

	result, err := client.ValidatePolicy(ctx, input)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("failed to validate policy: %s", err.Error()))
		resp.Error = function.NewFuncError(fmt.Sprintf("ValidatePolicy error: %s", err.Error()))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("ValidatePolicyFunction found %d findings", len(result.Findings)))
	tflog.Info(ctx, fmt.Sprintf("Findings: %+v", result.Findings))

	errors := []attr.Value{}
	for _, finding := range result.Findings {
		msg, _ := json.Marshal(finding)
		errors = append(errors, types.StringValue(string(msg)))
	}

	outputObj, diags := types.ObjectValue(validatePolicyReturnAttrTypes, map[string]attr.Value{
		"errors": types.ListValueMust(types.StringType, errors),
	})
	resp.Error = function.FuncErrorFromDiags(ctx, diags)
	if resp.Error != nil {
		return
	}
	resp.Error = resp.Result.Set(ctx, &outputObj)
}
