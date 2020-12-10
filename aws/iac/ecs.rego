package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0047-CFR
#

default ecs_task_evelated = null

aws_attribute_absence["ecs_task_evelated"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ContainerDefinitions
}

aws_issue["ecs_task_evelated"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions[_].Privileged == true
}

ecs_task_evelated {
    lower(input.resources[_].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_task_evelated"]
    not aws_attribute_absence["ecs_task_evelated"]
}

ecs_task_evelated = false {
    aws_issue["ecs_task_evelated"]
}

ecs_task_evelated = false {
    aws_attribute_absence["ecs_task_evelated"]
}

ecs_task_evelated_err = "AWS ECS task definition elevated privileges enabled" {
    aws_issue["ecs_task_evelated"]
}

ecs_task_evelated_miss_err = "ECS taskdefinition attribute ContainerDefinitions missing in the resource" {
    aws_attribute_absence["ecs_task_evelated"]
}

#
# PR-AWS-0048-CFR
#

default ecs_exec = null

aws_attribute_absence["ecs_exec"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ExecutionRoleArn
}

aws_issue["ecs_exec"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not startswith(lower(resource.Properties.ExecutionRoleArn), "arn:aws:iam")
}

ecs_exec {
    lower(input.resources[_].Type) == "aws::ecs::taskdefinition"
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

ecs_exec_miss_err = "ECS taskdefinition attribute ExecutionRoleArn missing in the resource" {
    aws_attribute_absence["ecs_exec"]
}

#
# PR-AWS-0049-CFR
#

default ecs_root_user = null

aws_attribute_absence["ecs_root_user"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ContainerDefinitions
}

aws_issue["ecs_root_user"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.ContainerDefinitions[_].User) == "root"
}

ecs_root_user {
    lower(input.resources[_].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_root_user"]
    not aws_attribute_absence["ecs_root_user"]
}

ecs_root_user = false {
    aws_issue["ecs_root_user"]
}

ecs_root_user = false {
    aws_attribute_absence["ecs_root_user"]
}

ecs_root_user_err = "AWS ECS/Fargate task definition root user found" {
    aws_issue["ecs_root_user"]
}

ecs_root_user_miss_err = "ECS taskdefinition attribute ContainerDefinitions missing in the resource" {
    aws_attribute_absence["ecs_root_user"]
}
