package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# PR-AWS-0036-TRF
#

default dynabodb_encrypt = null

aws_attribute_absence["dynabodb_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    not resource.properties.server_side_encryption
}

aws_issue["dynabodb_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    not resource.properties.server_side_encryption.enabled
}

dynabodb_encrypt {
    lower(input.json.resources[_].type) == "aws_dynamodb_table"
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

dynabodb_encrypt_miss_err = "DynamoDB attribute server_side_encryption missing in the resource" {
    aws_attribute_absence["dynabodb_encrypt"]
}
