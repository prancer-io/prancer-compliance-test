package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# PR-AWS-0036-CFR
#

default dynamodb_encrypt = null

aws_attribute_absence["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.SSESpecification.SSEType
}

aws_issue["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.SSESpecification.SSEType) == "aes256"
}

dynamodb_encrypt {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
    not aws_issue["dynamodb_encrypt"]
    not aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynamodb_encrypt"]
}

dynamodb_encrypt_miss_err = "DynamoDB attribute SSEType missing in the resource" {
    aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-0036-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}

