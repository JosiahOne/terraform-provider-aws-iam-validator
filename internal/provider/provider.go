package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider              = &ExampleTimeProvider{}
	_ provider.ProviderWithFunctions = &ExampleTimeProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ExampleTimeProvider{
			version: version,
		}
	}
}

// ExampleTimeProvider is the provider implementation.
type ExampleTimeProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// Metadata returns the provider type name.
func (p *ExampleTimeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "aws-iam-validator"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *ExampleTimeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

// Configure prepares an API client for data sources and resources.
func (p *ExampleTimeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// DataSources defines the data sources implemented in the provider.
func (p *ExampleTimeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources defines the resources implemented in the provider.
func (p *ExampleTimeProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

// Functions defines the functions implemented in the provider.
func (p *ExampleTimeProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}
