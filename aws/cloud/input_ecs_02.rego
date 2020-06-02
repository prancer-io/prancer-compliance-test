package rule

default rulepass = false

rulepass = true{
   	not input.taskDefinition.containerDefinitions[0].user
}

rulepass = true{
   	input.taskDefinition.containerDefinitions[0].user!="root"
}
