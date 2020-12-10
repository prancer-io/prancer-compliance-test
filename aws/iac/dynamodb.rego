package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# PR-AWS-0036-CFR
#

default dynabodb_encrypt = null

aws_attribute_absence["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.SSESpecification.SSEType
}

aws_issue["dynabodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.SSESpecification.SSEType) == "aes256"
}

dynabodb_encrypt {
    lower(input.resources[_].Type) == "aws::dynamodb::table"
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
}

dynabodb_encrypt_miss_err = "DynamoDB attribute SSEType missing in the resource" {
    aws_attribute_absence["dynabodb_encrypt"]
}

