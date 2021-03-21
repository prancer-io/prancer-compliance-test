#
# PR-AWS-0155
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html

rulepass {
    lower(input.Type) == "aws::sqs::queue"
    input.Attributes.RedrivePolicy
    contains(lower(input.Attributes.RedrivePolicy), "deadlettertargetarn")
}
