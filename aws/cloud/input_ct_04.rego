#
# PR-AWS-0192
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html

rulepass = true{
   input.trailList[_].CloudWatchLogsLogGroupArn
   input.trailList[_].CloudWatchLogsRoleArn
}
