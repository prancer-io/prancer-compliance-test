package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html

#
# PR-AWS-0014-TRF
#

default cf_sns = null

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.notification_arns
}

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    count(resource.properties.notification_arns) == 0
}

cf_sns {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["cf_sns"]
}

cf_sns = false {
    aws_issue["cf_sns"]
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    aws_issue["cf_sns"]
}

cf_sns_metadata := {
    "Policy Code": "PR-AWS-0014-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html"
}
