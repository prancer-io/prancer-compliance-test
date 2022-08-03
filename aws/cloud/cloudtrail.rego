package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

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

#
# PR-AWS-CLD-CT-005
#

default logging_data_events_for_s3_and_lambda = false

logging_data_events_for_s3_and_lambda = true {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    event := input.EventSelectors[i]
    resource := event.DataResources[j]
    contains(lower(resource.Type), "aws::s3::object")
}

logging_data_events_for_s3_and_lambda = true {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    event := input.EventSelectors[i]
    resource := event.DataResources[j]
    contains(lower(resource.Type), "aws::lambda::function")
}

logging_data_events_for_s3_and_lambda_err = "Ensure AWS CloudTrail is logging data events for S3 and Lambda." {
    not logging_data_events_for_s3_and_lambda
}

logging_data_events_for_s3_and_lambda_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS CloudTrail is logging data events for S3 and Lambda.",
    "Policy Description": "It checks that CloudTrail data event is enabled for S3 and Lambda.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.get_event_selectors"
}

#
# PR-AWS-CLD-CT-006
#

default cloudtrail_is_enabled = true

cloudtrail_is_enabled = false {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    count(input.trailList[_]) == 0
}

cloudtrail_is_enabled_err = "Ensure AWS CloudTrail is enabled on the account." {
    not cloudtrail_is_enabled
}

cloudtrail_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS CloudTrail is enabled on the account.",
    "Policy Description": "AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail to get a complete audit trail of activities across various services.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails"
}


#
# PR-AWS-CLD-CT-007
# aws::cloudtrail::trail

default cloudtrail_logging_is_enabled = true

cloudtrail_logging_is_enabled = false {
    not input.IsLogging
}

cloudtrail_logging_is_enabled = false {
    input.IsLogging == "false"
}

cloudtrail_logging_is_enabled_err = "Ensure AWS CloudTrail logging is enabled." {
    not cloudtrail_logging_is_enabled
}

cloudtrail_logging_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS CloudTrail logging is enabled.",
    "Policy Description": "It identifies the CloudTrails in which logging is disabled. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on logging for CloudTrail across different regions to get a complete audit trail of activities across various services. NOTE: This policy will be triggered only when you have CloudTrail configured in your AWS account and logging is disabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails"
}


#
# PR-AWS-CLD-CT-008
# aws::cloudtrail::trail

default cloudtrail_with_cloudwatch = true

cloudtrail_with_cloudwatch = false {
    has_property(input, CloudWatchLogsLogGroupArn)
    input.CloudWatchLogsLogGroupArn != ""
    input.IsMultiRegionTrail == false
    has_property(input, LatestCloudWatchLogsDeliveryTime)
}

cloudtrail_with_cloudwatch = false {
    input.IsLogging == "false"
}

cloudtrail_with_cloudwatch_err = "Ensure AWS CloudTrail logs is integrated with CloudWatch for all regions." {
    not cloudtrail_with_cloudwatch
}

cloudtrail_with_cloudwatch_metadata := {
    "Policy Code": "PR-AWS-CLD-CT-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS CloudTrail logs is integrated with CloudWatch for all regions.",
    "Policy Description": "It identifies the Cloudtrails which is not integrated with cloudwatch for all regions. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.describe_trails"
}