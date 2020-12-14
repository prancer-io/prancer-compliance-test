#
# PR-AWS-0049
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    not input.taskDefinition.containerDefinitions[0].user
}

rulepass {
    lower(input.taskDefinition.containerDefinitions[0].user) != "root"
}
