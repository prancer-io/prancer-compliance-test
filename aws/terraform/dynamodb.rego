package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# PR-AWS-0036-TRF
#

default dynabodb_encrypt = null

aws_attribute_absence["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    not resource.properties.server_side_encryption
}

aws_issue["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    count([c | resource.properties.server_side_encryption[_]; c:=1]) == 0
}

aws_issue["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    server_side_encryption := resource.properties.server_side_encryption[_]
    lower(server_side_encryption.enabled) == "false"
}

aws_bool_issue["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    server_side_encryption := resource.properties.server_side_encryption[_]
    not server_side_encryption.enabled
}

dynabodb_encrypt {
    lower(input.resources[_].type) == "aws_dynamodb_table"
    not aws_issue["dynabodb_encrypt"]
    not aws_bool_issue["dynabodb_encrypt"]
    not aws_attribute_absence["dynabodb_encrypt"]
}

dynabodb_encrypt = false {
    aws_issue["dynabodb_encrypt"]
}

dynabodb_encrypt = false {
    aws_bool_issue["dynabodb_encrypt"]
}

dynabodb_encrypt = false {
    aws_attribute_absence["dynabodb_encrypt"]
}

dynabodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynabodb_encrypt"]
} else = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_bool_issue["dynabodb_encrypt"]
} else = "DynamoDB attribute server_side_encryption missing in the resource" {
    aws_attribute_absence["dynabodb_encrypt"]
}

dynabodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-0036-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Resource Type": "aws_dynamodb_table",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}


#
# PR-AWS-0258-TRF
#

default dynamodb_PITR_enable = null

aws_issue["dynamodb_PITR_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    point_in_time_recovery := resource.properties.point_in_time_recovery[_]
    lower(point_in_time_recovery.enabled) != "true"
}

aws_bool_issue["dynamodb_PITR_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    point_in_time_recovery := resource.properties.point_in_time_recovery[_]
    not point_in_time_recovery.enabled
}

dynamodb_PITR_enable {
    lower(input.resources[i].type) == "aws_dynamodb_table"
    not aws_issue["dynamodb_PITR_enable"]
    not aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable = false {
    aws_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable = false {
    aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable_err = "Ensure DynamoDB PITR is enabled" {
    aws_issue["dynamodb_PITR_enable"]
} else = "Ensure DynamoDB PITR is enabled" {
    aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable_metadata := {
    "Policy Code": "PR-AWS-0258-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure DynamoDB PITR is enabled",
    "Policy Description": "DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}
