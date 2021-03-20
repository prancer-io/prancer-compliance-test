#
# PR-AWS-0047
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    lower(resource.Type) == "aws::ecs::taskdefinition"
    input.taskDefinition.containerDefinitions[_].privileged == false
}
