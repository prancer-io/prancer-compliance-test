#
# PR-AWS-0061
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    lower(input.Type) == "aws::efs::filesystem"
    input.FileSystems[_].Encrypted == false
}

metadata := {
    "Policy Code": "PR-AWS-0061",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html"
}
