#
# PR-AWS-0028
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html

rulepass = true {
    # lower(input.json.Type) == "aws::cloudtrail::trail"
    input.json.trailList[_].KmsKeyId
}

metadata := {
    "Policy Code": "PR-AWS-0028",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0028-DESC risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}
