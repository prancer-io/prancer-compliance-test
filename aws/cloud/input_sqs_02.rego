package rule

default rulepass = false


rulepass = true{
	input.Attributes.KmsMasterKeyId
}

# if the Server Side Encryption is configured then test will pass