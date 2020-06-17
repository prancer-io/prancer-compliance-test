package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html
# Id: 28

rulepass = true{
   input.trailList[_].KmsKeyId
}
