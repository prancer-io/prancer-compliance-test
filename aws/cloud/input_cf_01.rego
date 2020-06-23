package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html
# Id: 14


rulepass = true{
   count(input.Stacks[_].NotificationARNs) > 0
}
