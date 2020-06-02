package rule

default rulepass = false

rulepass = true{
	input.taskDefinition.containerDefinitions[_].privileged=false
}
