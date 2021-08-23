package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# PR-AWS-0036-CFR
#

default dynamodb_encrypt = null

aws_issue["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.SSESpecification.SSEEnabled) != "true"
}

aws_bool_issue["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.SSESpecification.SSEEnabled
}

dynamodb_encrypt {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
    not aws_issue["dynamodb_encrypt"]
    not aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynamodb_encrypt"]
} else = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-0036-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}


#
# PR-AWS-0258-CFR
#

default dynamodb_PITR_enable = null

aws_issue["dynamodb_PITR_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled) != "true"
}

aws_bool_issue["dynamodb_PITR_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled
}

dynamodb_PITR_enable {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
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
    "Policy Code": "PR-AWS-0258-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DynamoDB PITR is enabled",
    "Policy Description": "DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}
