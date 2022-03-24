package rule

# https://docs.aws.amazon.com/awscloudtrail/latest/APIReference

#
# PR-AWS-CLD-CT-001
#

default ct_regions = true

ct_regions = false {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    input.trailList[_].IsMultiRegionTrail == false
}

ct_regions_err = "AWS CloudTrail is not enabled in all regions" {
    not ct_regions
}

ct_regions_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudTrail is not enabled in all regions",
    "Policy Description": "Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}


#
# PR-AWS-CLD-CT-002
#

default ct_log_validation = true

ct_log_validation = false {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    input.trailList[_].LogFileValidationEnabled == false
}

ct_log_validation_err = "AWS CloudTrail log validation is not enabled in all regions" {
    not ct_log_validation
}

ct_log_validation_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}

#
# PR-AWS-CLD-CT-003
#

default ct_master_key = true

ct_master_key = false {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    trailList := input.trailList[_]
    not trailList.KmsKeyId
}

ct_master_key_err = "AWS CloudTrail is not enabled in all regions" {
    not ct_master_key
}

ct_master_key_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}

#
# PR-AWS-CLD-CT-004
#

default ct_cloudwatch = true

ct_cloudwatch = false {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    trailList := input.trailList[_]
    not trailList.CloudWatchLogsRoleArn
    not trailList.CloudWatchLogsLogGroupArn
}

ct_cloudwatch_err = "AWS CloudTrail is not enabled in all regions" {
    not ct_cloudwatch
}

ct_cloudwatch_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "CloudTrail trail is not integrated with CloudWatch Log",
    "Policy Description": "Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}