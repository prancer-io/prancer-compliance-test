#
# PR-AWS-0156
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html

rulepass {
	input.Attributes.KmsMasterKeyId
}

# if the Server Side Encryption is configured then test will pass
