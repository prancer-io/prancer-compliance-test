package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0048-TRF
#

default ecs_exec = null

aws_attribute_absence["ecs_exec"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.execution_role_arn
}

aws_issue["ecs_exec"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_ecs_task_definition"
    not startswith(lower(resource.properties.execution_role_arn), "arn:aws:iam")
}

ecs_exec {
    lower(input.resources[_].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_exec"]
    not aws_attribute_absence["ecs_exec"]
}

ecs_exec = false {
    aws_issue["ecs_exec"]
}

ecs_exec = false {
    aws_attribute_absence["ecs_exec"]
}

ecs_exec_err = "AWS ECS/Fargate task definition execution IAM Role not found" {
    aws_issue["ecs_exec"]
} else = "ECS taskdefinition attribute execution_role_arn missing in the resource" {
    aws_attribute_absence["ecs_exec"]
}

ecs_exec_metadata := {
    "Policy Code": "PR-AWS-0048-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS/Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "aws_ecs_task_definition",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}
