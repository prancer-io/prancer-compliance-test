#
# PR-AWS-0157
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html

rulepass {
    input.Attributes.KmsMasterKeyId
    lower(input.Attributes.KmsMasterKeyId) != "alias/aws/sqs"
}

# if the Server Side Encryption is configured then test will pass
