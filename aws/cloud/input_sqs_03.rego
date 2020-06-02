package rule

default rulepass = false


rulepass = true{
	input.Attributes.KmsMasterKeyId
    input.Attributes.KmsMasterKeyId!="alias/aws/sqs"
}

# if the Server Side Encryption is configured then test will pass