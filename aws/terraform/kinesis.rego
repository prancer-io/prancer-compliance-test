package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html
#
# PR-AWS-0233-TRF
#
default kinesis_encryption = null

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.yype) == "aws_kinesis_stream"
    not resource.properties.encryption_type
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    count(resource.properties.encryption_type) == 0
}

kinesis_encryption {
    lower(input.resources[i].type) == "aws_kinesis_stream"
    not aws_issue["kinesis_encryption"]
}

kinesis_encryption = false {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_err = "AWS Kinesis streams are not encrypted using Server Side Encryption" {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_metadata := {
    "Policy Code": "PR-AWS-0233-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Kinesis streams are not encrypted using Server Side Encryption",
    "Policy Description": "This Policy identifies the AWS Kinesis streams which are not encrypted using Server Side Encryption. Server Side Encryption is used to encrypt your sensitive data before it is written to the Kinesis stream storage layer and decrypted after it is retrieved from storage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}

#
# PR-AWS-0234-TRF
#

default kinesis_encryption_kms = null

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    lower(resource.properties.encryption_type) != "kms"
}

kinesis_encryption_kms {
    lower(input.resources[i].type) == "aws_kinesis_stream"
    not aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms = false {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_err = "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys" {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-0234-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys",
    "Policy Description": "This policy identifies the AWS Kinesis streams which are encrypted with default KMS keys and not with Master Keys managed by Customer. It is a best practice to use customer managed Master Keys to encrypt your Amazon Kinesis streams data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}
