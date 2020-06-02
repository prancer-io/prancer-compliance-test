package rule

default rulepass = false


rulepass = true{
	input.Attributes.RedrivePolicy
    contains(input.Attributes.RedrivePolicy, "deadLetterTargetArn")
}