#
# PR-AWS-0047
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html

rulepass {
    # lower(input.json.Type) == "aws::ecs::taskdefinition"
    input.json.taskDefinition.containerDefinitions[_].privileged == false
}

metadata := {
    "Policy Code": "PR-AWS-0047",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance._x005F_x000D_ _x005F_x000D_ When the Privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user)._x005F_x000D_ _x005F_x000D_ This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled._x005F_x000D_ _x005F_x000D_ Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html"
}
