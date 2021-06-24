#
# PR-AWS-0014
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html

rulepass = true {
    # lower(input.Type) == "aws::cloudformation::stack"
    count(input.Stacks[_].NotificationARNs) > 0
}

metadata := {
    "Policy Code": "PR-AWS-0014",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html"
}
