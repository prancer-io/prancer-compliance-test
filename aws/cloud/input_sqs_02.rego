package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html
# Id: 156

rulepass = true{
	input.Attributes.KmsMasterKeyId
}

# if the Server Side Encryption is configured then test will pass