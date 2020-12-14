package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0048-TRF
#

default ecs_exec = null

aws_attribute_absence["ecs_exec"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.execution_role_arn
}

aws_issue["ecs_exec"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_ecs_task_definition"
    not startswith(lower(resource.properties.execution_role_arn), "arn:aws:iam")
}

ecs_exec {
    lower(input.json.resources[_].type) == "aws_ecs_task_definition"
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
}

ecs_exec_miss_err = "ECS taskdefinition attribute execution_role_arn missing in the resource" {
    aws_attribute_absence["ecs_exec"]
}
