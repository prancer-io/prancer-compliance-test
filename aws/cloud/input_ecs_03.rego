package rule

default rulepass = false

rulepass = true{
	startswith(input.taskDefinition.executionRoleArn, "arn:aws:iam")	
}
