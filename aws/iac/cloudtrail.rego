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
