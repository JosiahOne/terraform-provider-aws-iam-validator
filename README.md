# terraform-provider-aws-iam-validator
https://registry.terraform.io/providers/JosiahOne/aws-iam-validator/latest

This terraform provider includes a terraform function and data source that can be used to validate any IAM policy documents.

Behind the scenes it calls the ValidatePolicy AWS API and returns a list of findings. This is especially
helpful for writing terraform checks e.g.

## Function case

```
check "valid_check" {
  assert {
    condition = length(provider::aws-iam-validator::validate_policy(local.iam_data)) == 0
    error_message = "IAM policy is not valid"
  }
}
```

## Datasource case

```
data "aws-iam-validator" "example" {
  policy_json = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [...]
  }
  EOF
}

check "valid_check" {
  assert {
    condition = length(data.aws-iam-validator.example.findings) == 0
    error_message = "IAM policy is not valid"
  }
}
```
