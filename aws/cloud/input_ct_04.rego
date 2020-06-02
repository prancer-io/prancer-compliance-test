package rule

default rulepass = false

rulepass = true{
   input.trailList[_].CloudWatchLogsLogGroupArn
   input.trailList[_].CloudWatchLogsRoleArn
}
