#
# PR-AWS-0048
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    lower(resource.Type) == "aws::ecs::taskdefinition"
    startswith(input.taskDefinition.executionRoleArn, "arn:aws:iam")
}
