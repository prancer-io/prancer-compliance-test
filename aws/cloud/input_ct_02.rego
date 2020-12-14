#
# PR-AWS-0027
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html

rulepass = true{
   input.trailList[_].LogFileValidationEnabled=true
}
