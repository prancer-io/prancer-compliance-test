package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html

#
# PR-AWS-0026-TRF
#

default ct_regions = null

aws_issue["ct_regions"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    lower(resource.properties.is_multi_region_trail) == "false"
}

aws_bool_issue["ct_regions"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.is_multi_region_trail
}

ct_regions {
    lower(input.resources[_].type) == "aws_cloudtrail"
    not aws_issue["ct_regions"]
    not aws_bool_issue["ct_regions"]
}

ct_regions = false {
    aws_issue["ct_regions"]
}

ct_regions = false {
    aws_bool_issue["ct_regions"]
}

ct_regions_err = "AWS CloudTrail is not enabled in all regions" {
    aws_issue["ct_regions"]
} else = "AWS CloudTrail is not enabled in all regions" {
    aws_bool_issue["ct_regions"]
}

ct_regions_metadata := {
    "Policy Code": "PR-AWS-0026-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudTrail is not enabled in all regions",
    "Policy Description": "Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0026-TRF-DESC risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.",
    "Resource Type": "aws_cloudtrail",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-0027-TRF
#

default ct_log_validation = null

aws_issue["ct_log_validation"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    lower(resource.properties.enable_log_file_validation) == "false"
}

aws_bool_issue["ct_log_validation"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.enable_log_file_validation
}

ct_log_validation {
    lower(input.resources[_].type) == "aws_cloudtrail"
    not aws_issue["ct_log_validation"]
    not aws_bool_issue["ct_log_validation"]
}

ct_log_validation = false {
    aws_issue["ct_log_validation"]
}

ct_log_validation = false {
    aws_bool_issue["ct_log_validation"]
}

ct_log_validation_err = "AWS CloudTrail log validation is not enabled in all regions" {
    aws_issue["ct_log_validation"]
} else = "AWS CloudTrail log validation is not enabled in all regions" {
    aws_issue["ct_log_validation"]
}


ct_log_validation_metadata := {
    "Policy Code": "PR-AWS-0027-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Resource Type": "aws_cloudtrail",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
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
} else = "CloudTrail attribute kms_key_id missing in the resource" {
    aws_attribute_absence["ct_master_key"]
}

ct_master_key_metadata := {
    "Policy Code": "PR-AWS-0028-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0028-TRF-DESC risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Resource Type": "aws_cloudtrail",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
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
} else = "CloudTrail attribute cloud_watch_logs_role_arn missing in the resource" {
    aws_attribute_absence["ct_cloudwatch"]
}

ct_cloudwatch_metadata := {
    "Policy Code": "PR-AWS-0192-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "CloudTrail trail is not integrated with CloudWatch Log",
    "Policy Description": "Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.",
    "Resource Type": "aws_cloudtrail",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}
