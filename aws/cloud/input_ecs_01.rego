package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html
# Id: 47

rulepass = true{
	input.taskDefinition.containerDefinitions[_].privileged=false
}
