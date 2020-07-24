package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html

#
# Id: 14
#

default cf_sns = null

aws_attribute_absence["cf_sns"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudformation::stack"
    not resource.Properties.NotificationARNs
}

aws_issue["cf_sns"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudformation::stack"
    count(resource.Properties.NotificationARNs) == 0
}

cf_sns {
    lower(input.resources[_].Type) == "aws::cloudformation::stack"
    not aws_issue["cf_sns"]
    not aws_attribute_absence["cf_sns"]
}

cf_sns = false {
    aws_issue["cf_sns"]
}

cf_sns = false {
    aws_attribute_absence["cf_sns"]
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    aws_issue["cf_sns"]
}

cf_sns_miss_err = "CloudFormation attribute NotificationARNs missing in the resource" {
    aws_attribute_absence["cf_sns"]
}
