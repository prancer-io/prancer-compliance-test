package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html

#
# Id: 14
#

default cf_sns = null

cf_sns {
    lower(input.Type) == "aws::cloudformation::stack"
    count(input.Properties.NotificationARNs) > 0
}

cf_sns = false {
    lower(input.Type) == "aws::cloudformation::stack"
    count(input.Properties.NotificationARNs) == 0
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    cf_sns == false
}
