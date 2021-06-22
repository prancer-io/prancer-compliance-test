package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html

#
# PR-AWS-0014-CFR
#

default cf_sns = null

aws_attribute_absence["cf_sns"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    not resource.Properties.NotificationARNs
}

aws_issue["cf_sns"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    count(resource.Properties.NotificationARNs) == 0
}

cf_sns {
    lower(input.Resources[i].Type) == "aws::cloudformation::stack"
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

cf_sns_err = "CloudFormation attribute NotificationARNs missing in the resource" {
    aws_attribute_absence["cf_sns"]
}

cf_sns_metadata := {
    "Policy Code": "PR-AWS-0014-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html"
}
