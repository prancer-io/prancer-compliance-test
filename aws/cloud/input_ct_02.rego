#
# PR-AWS-0027
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html

rulepass = true {
    # lower(input.json.Type) == "aws::cloudtrail::trail"
    input.json.trailList[_].LogFileValidationEnabled=true
}

metadata := {
    "Policy Code": "PR-AWS-0027",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html"
}
