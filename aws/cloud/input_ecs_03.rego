#
# PR-AWS-0048
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    lower(input.Type) == "aws::ecs::taskdefinition"
    startswith(input.taskDefinition.executionRoleArn, "arn:aws:iam")
}

rulepass_metadata := {
    "Policy Code": "PR-AWS-0048",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS ECS/ Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html"
}
