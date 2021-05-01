package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html

#
# PR-AWS-0026-TRF
#

default ct_regions = null

aws_issue["ct_regions"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.is_multi_region_trail
}

ct_regions {
    lower(input.resources[_].type) == "aws_cloudtrail"
    not aws_issue["ct_regions"]
}

ct_regions = false {
    aws_issue["ct_regions"]
}

ct_regions_err = "AWS CloudTrail is not enabled in all regions" {
    aws_issue["ct_regions"]
}

#
# PR-AWS-0027-TRF
#

default ct_log_validation = null

aws_issue["ct_log_validation"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.enable_log_file_validation
}

ct_log_validation {
    lower(input.resources[_].type) == "aws_cloudtrail"
    not aws_issue["ct_log_validation"]
}

ct_log_validation = false {
    aws_issue["ct_log_validation"]
}

ct_log_validation_err = "AWS CloudTrail log validation is not enabled in all regions" {
    aws_issue["ct_log_validation"]
}

#
# PR-AWS-0028-TRF
#

default ct_master_key = null

aws_attribute_absence["ct_master_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.kms_key_id
}

aws_issue["ct_master_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    count(resource.properties.kms_key_id) == 0
}

ct_master_key {
    lower(input.resources[_].type) == "aws_cloudtrail"
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

ct_master_key_miss_err = "CloudTrail attribute kms_key_id missing in the resource" {
    aws_attribute_absence["ct_master_key"]
}

#
# PR-AWS-0192-TRF
#

default ct_cloudwatch = null

aws_attribute_absence["ct_cloudwatch"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.cloud_watch_logs_role_arn
}

aws_issue["ct_cloudwatch"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    count(resource.properties.cloud_watch_logs_role_arn) == 0
}

ct_cloudwatch {
    lower(input.resources[_].type) == "aws_cloudtrail"
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

ct_cloudwatch_miss_err = "CloudTrail attribute cloud_watch_logs_role_arn missing in the resource" {
    aws_attribute_absence["ct_cloudwatch"]
}
