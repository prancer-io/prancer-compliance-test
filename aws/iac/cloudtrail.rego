package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html

#
# Id: 26
#

default ct_regions = null

ct_regions {
    lower(input.Type) == "aws::cloudtrail::trail"
    input.Properties.IsMultiRegionTrail == true
}

ct_regions = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    input.Properties.IsMultiRegionTrail == false
}

ct_regions_err = "AWS CloudTrail is not enabled in all regions" {
    ct_regions == false
}

#
# Id: 27
#

default ct_log_validation = null

ct_log_validation {
    lower(input.Type) == "aws::cloudtrail::trail"
    input.Properties.EnableLogFileValidation == true
}

ct_log_validation = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    input.Properties.EnableLogFileValidation == false
}

ct_log_validation_err = "AWS CloudTrail log validation is not enabled in all regions" {
    ct_log_validation == false
}

#
# Id: 28
#

default ct_master_key = null

ct_master_key {
    lower(input.Type) == "aws::cloudtrail::trail"
    count(input.Properties.KMSKeyId) > 0
}

ct_master_key = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    not input.Properties.KMSKeyId
}

ct_master_key = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    count(input.Properties.KMSKeyId) == 0
}

ct_master_key_err = "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)" {
    ct_master_key == false
}

#
# Id: 268
#

default ct_cloudwatch = null

ct_cloudwatch {
    lower(input.Type) == "aws::cloudtrail::trail"
    count(input.Properties.CloudWatchLogsRoleArn) > 0
}

ct_cloudwatch = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    not input.Properties.CloudWatchLogsRoleArn
}

ct_cloudwatch = false {
    lower(input.Type) == "aws::cloudtrail::trail"
    count(input.Properties.CloudWatchLogsRoleArn) == 0
}

ct_cloudwatch_err = "CloudTrail trail is not integrated with CloudWatch Log" {
    ct_cloudwatch == false
}
