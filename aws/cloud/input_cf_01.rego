package rule

default rulepass = false

# API Reference : 
# Id: 14


rulepass = true{
   count(input.Stacks[_].NotificationARNs) > 0
}
