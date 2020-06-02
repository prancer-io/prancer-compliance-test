package rule

default rulepass = false

rulepass = true{
   count(input.Stacks[_].NotificationARNs) > 0
}
