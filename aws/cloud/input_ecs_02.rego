#
# PR-AWS-0049
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    lower(input.Type) == "aws::ecs::taskdefinition"
    not input.taskDefinition.containerDefinitions[0].user
}

rulepass {
    lower(input.Type) == "aws::ecs::taskdefinition"
    lower(input.taskDefinition.containerDefinitions[0].user) != "root"
}

metadata := {
    "Policy Code": "PR-AWS-0049",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition._x005F_x000D_ _x005F_x000D_ The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run_x005F_x000D_ _x005F_x000D_ Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html"
}
