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
    count([c | resource.properties.server_side_encryption; c:=1]) == 0
}

aws_issue["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    count([c | resource.properties.server_side_encryption; c:=1]) == 0
    server_side_encryption := resource.properties.server_side_encryption[_]
    not server_side_encryption.enabled
}

dynabodb_encrypt {
    lower(input.resources[_].type) == "aws_dynamodb_table"
    not aws_issue["dynabodb_encrypt"]
    not aws_attribute_absence["dynabodb_encrypt"]
}

dynabodb_encrypt = false {
    aws_issue["dynabodb_encrypt"]
}

dynabodb_encrypt = false {
    aws_attribute_absence["dynabodb_encrypt"]
}

dynabodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynabodb_encrypt"]
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
