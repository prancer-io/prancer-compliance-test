package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html
# Id: 155

rulepass {
	input.Attributes.RedrivePolicy
    contains(lower(input.Attributes.RedrivePolicy), "deadlettertargetarn")
}
