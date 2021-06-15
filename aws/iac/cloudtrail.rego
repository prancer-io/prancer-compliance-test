package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html

#
# PR-AWS-0026-CFR
#

default ct_regions = null

aws_issue["ct_regions"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.IsMultiRegionTrail
}

ct_regions {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_regions"]
}

ct_regions = false {
    aws_issue["ct_regions"]
}

ct_regions_err = "AWS CloudTrail is not enabled in all regions" {
    aws_issue["ct_regions"]
}

ct_regions_metadata := {
    "Policy Code": "PR-AWS-0026-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail is not enabled in all regions",
    "Policy Description": "Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0026-CFR-DESC risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.",
    "Compliance": ["CIS","GDPR","HIPAA","HITRUST","ISO 27001","NIST 800","PCI-DSS","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-0027-CFR
#

default ct_log_validation = null

aws_issue["ct_log_validation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.EnableLogFileValidation
}

ct_log_validation {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_log_validation"]
}

ct_log_validation = false {
    aws_issue["ct_log_validation"]
}

ct_log_validation_err = "AWS CloudTrail log validation is not enabled in all regions" {
    aws_issue["ct_log_validation"]
}

ct_log_validation_metadata := {
    "Policy Code": "PR-AWS-0027-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Compliance": ["CIS","CSA-CCM","GDPR","HIPAA","HITRUST","ISO 27001","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-0028-CFR
#

default ct_master_key = null

aws_attribute_absence["ct_master_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.KMSKeyId
}

aws_issue["ct_master_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.KMSKeyId) == 0
}

ct_master_key {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_master_key"]
    not aws_attribute_absence["ct_master_key"]
}

ct_master_key = false {
    aws_issue["ct_master_key"]
}

ct_master_key = false {
    aws_attribute_absence["ct_master_key"]
}

ct_master_key_err = "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)" {
    aws_issue["ct_master_key"]
}

ct_master_key_miss_err = "CloudTrail attribute KMSKeyId missing in the resource" {
    aws_attribute_absence["ct_master_key"]
}

ct_master_key_metadata := {
    "Policy Code": "PR-AWS-0028-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0028-CFR-DESC risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Compliance": ["CIS","CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-0192-CFR
#

default ct_cloudwatch = null

aws_attribute_absence["ct_cloudwatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.CloudWatchLogsRoleArn
}

aws_issue["ct_cloudwatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.CloudWatchLogsRoleArn) == 0
}

ct_cloudwatch {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_cloudwatch"]
    not aws_attribute_absence["ct_cloudwatch"]
}

ct_cloudwatch = false {
    aws_issue["ct_cloudwatch"]
}

ct_cloudwatch = false {
    aws_attribute_absence["ct_cloudwatch"]
}

ct_cloudwatch_err = "CloudTrail trail is not integrated with CloudWatch Log" {
    aws_issue["ct_cloudwatch"]
}

ct_cloudwatch_miss_err = "CloudTrail attribute CloudWatchLogsRoleArn missing in the resource" {
    aws_attribute_absence["ct_cloudwatch"]
}

ct_cloudwatch_metadata := {
    "Policy Code": "PR-AWS-0192-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "CloudTrail trail is not integrated with CloudWatch Log",
    "Policy Description": "Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.",
    "Compliance": ["CIS","CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}
