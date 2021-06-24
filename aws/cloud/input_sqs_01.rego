#
# PR-AWS-0155
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html

rulepass {
    # lower(input.Type) == "aws::sqs::queue"
    input.Attributes.RedrivePolicy
    contains(lower(input.Attributes.RedrivePolicy), "deadlettertargetarn")
}

metadata := {
    "Policy Code": "PR-AWS-0155",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS SQS does not have a dead letter queue configured",
    "Policy Description": "This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html"
}
