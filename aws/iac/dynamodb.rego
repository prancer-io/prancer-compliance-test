package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html

#
# Id: 36
#

default dynabodb_encrypt = null

dynabodb_encrypt {
    lower(input.Type) == "aws::dynamodb::table"
    lower(input.Properties.SSESpecification.SSEType) != "aes256"
}

dynabodb_encrypt {
    lower(input.Type) == "aws::dynamodb::table"
    not input.Properties.SSESpecification.SSEType
}

dynabodb_encrypt = false {
    lower(input.Type) == "aws::dynamodb::table"
    lower(input.Properties.SSESpecification.SSEType) == "aes256"
}

dynabodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    dynabodb_encrypt == false
}
