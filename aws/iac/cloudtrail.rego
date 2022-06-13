package rule
default metadata = {}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html

#
# PR-AWS-CFR-CT-001
#

default ct_regions = null

aws_issue["ct_regions"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.IsMultiRegionTrail) != "true"
}
aws_bool_issue["ct_regions"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.IsMultiRegionTrail
}

source_path[{"ct_regions": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.IsMultiRegionTrail) != "true"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "IsMultiRegionTrail"]],
    }
}
source_path[{"ct_regions": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.IsMultiRegionTrail
    metadata := {
        "resource_path": [["Resources", i, "Properties", "IsMultiRegionTrail"]],
    }
}

ct_regions {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
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
} else = "AWS CloudTrail is not enabled in all regions"{
    aws_bool_issue["ct_regions"]
}

ct_regions_metadata := {
    "Policy Code": "PR-AWS-CFR-CT-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail is not enabled in all regions",
    "Policy Description": "Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-CFR-CT-002
#

default ct_log_validation = null

aws_issue["ct_log_validation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.EnableLogFileValidation) != "true"
}
aws_bool_issue["ct_log_validation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.EnableLogFileValidation
}

source_path[{"ct_log_validation": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.EnableLogFileValidation) != "true"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "EnableLogFileValidation"]],
    }
}
source_path[{"ct_log_validation": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.EnableLogFileValidation
    metadata := {
        "resource_path": [["Resources", i, "Properties", "EnableLogFileValidation"]],
    }
}

ct_log_validation {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
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
    aws_bool_issue["ct_log_validation"]
}

ct_log_validation_metadata := {
    "Policy Code": "PR-AWS-CFR-CT-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-CFR-CT-003
#

default ct_master_key = null

aws_issue["ct_master_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.KMSKeyId
}

aws_issue["ct_master_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.KMSKeyId) == 0
}

source_path[{"ct_master_key": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.KMSKeyId
    metadata := {
        "resource_path": [["Resources", i, "Properties", "KMSKeyId"]],
    }
}

source_path[{"ct_master_key": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.KMSKeyId) == 0
    metadata := {
        "resource_path": [["Resources", i, "Properties", "KMSKeyId"]],
    }
}

ct_master_key {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_master_key"]
}

ct_master_key = false {
    aws_issue["ct_master_key"]
}

ct_master_key_err = "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)" {
    aws_issue["ct_master_key"]
}

ct_master_key_metadata := {
    "Policy Code": "PR-AWS-CFR-CT-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-CFR-CT-004
#

default ct_cloudwatch = null

aws_issue["ct_cloudwatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.CloudWatchLogsRoleArn
    not resource.Properties.CloudWatchLogsLogGroupArn
}

aws_issue["ct_cloudwatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.CloudWatchLogsRoleArn) == 0
    count(resource.Properties.CloudWatchLogsLogGroupArn) == 0
}

source_path[{"ct_cloudwatch": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.CloudWatchLogsRoleArn
    not resource.Properties.CloudWatchLogsLogGroupArn

    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CloudWatchLogsRoleArn"],
            ["Resources", i, "Properties", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

source_path[{"ct_cloudwatch": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.CloudWatchLogsRoleArn) == 0
    count(resource.Properties.CloudWatchLogsLogGroupArn) == 0

    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CloudWatchLogsRoleArn"],
            ["Resources", i, "Properties", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

ct_cloudwatch {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["ct_cloudwatch"]
}

ct_cloudwatch = false {
    aws_issue["ct_cloudwatch"]
}

ct_cloudwatch_err = "CloudTrail trail is not integrated with CloudWatch Log" {
    aws_issue["ct_cloudwatch"]
}

ct_cloudwatch_metadata := {
    "Policy Code": "PR-AWS-CFR-CT-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "CloudTrail trail is not integrated with CloudWatch Log",
    "Policy Description": "Enabling the CloudTrail trail logs integrated with CloudWatch Logs will enable the real-time as well as historic activity logging. This will further effective monitoring and alarm capability.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-CFR-CT-005
#

default logging_data_events_for_s3_and_lambda = null

aws_issue["logging_data_events_for_s3_and_lambda"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    event := resource.Properties.EventSelectors[_]
    dataresource := event.DataResources[_]
    not contains(lower(dataresource.Type), "aws::s3::object")
    not contains(lower(dataresource.Type), "aws::lambda::function")
}

logging_data_events_for_s3_and_lambda {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["logging_data_events_for_s3_and_lambda"]
}

logging_data_events_for_s3_and_lambda = false {
    aws_issue["logging_data_events_for_s3_and_lambda"]
}

logging_data_events_for_s3_and_lambda_err = "Ensure AWS CloudTrail is logging data events for S3 and Lambda." {
    aws_issue["logging_data_events_for_s3_and_lambda"]
}

logging_data_events_for_s3_and_lambda_metadata := {
    "Policy Code": "PR-AWS-CFR-CT-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS CloudTrail is logging data events for S3 and Lambda.",
    "Policy Description": "It checks that CloudTrail data event is enabled for S3 and Lambda.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}
