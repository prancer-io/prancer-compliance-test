package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html
# Id: 

rulepass = true{
	input.FileSystems[_].Encrypted!=false
}
