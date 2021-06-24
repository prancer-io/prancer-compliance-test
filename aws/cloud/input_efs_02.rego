#
# PR-AWS-0060
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    # lower(input.json.Type) == "aws::efs::filesystem"
    input.json.FileSystems[_].Encrypted == false
}

rulepass = false {
    # lower(input.json.Type) == "aws::efs::filesystem"
    fs := input.json.FileSystems[_]
    not startswith(fs.KmsKeyId, "arn:")
}

metadata := {
    "Policy Code": "PR-AWS-0060",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html"
}
