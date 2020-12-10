#
# PR-AWS-0014
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html

rulepass = true{
   count(input.Stacks[_].NotificationARNs) > 0
}
