package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0047-CFR
#

default ecs_task_evelated = null

aws_attribute_absence["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ContainerDefinitions
}

aws_issue["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions[_].Privileged == true
}

ecs_task_evelated {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
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

ecs_task_evelated_err = "ECS taskdefinition attribute ContainerDefinitions missing in the resource" {
    aws_attribute_absence["ecs_task_evelated"]
}

ecs_task_evelated_metadata := {
    "Policy Code": "PR-AWS-0047-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance._x005F_x000D_ _x005F_x000D_ When the Privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user)._x005F_x000D_ _x005F_x000D_ This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled._x005F_x000D_ _x005F_x000D_ Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-0048-CFR
#

default ecs_exec = null

aws_attribute_absence["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ExecutionRoleArn
}

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not startswith(lower(resource.Properties.ExecutionRoleArn), "arn:aws:iam")
}

ecs_exec {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
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

ecs_exec_err = "ECS taskdefinition attribute ExecutionRoleArn missing in the resource" {
    aws_attribute_absence["ecs_exec"]
}

ecs_exec_metadata := {
    "Policy Code": "PR-AWS-0048-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS/ Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-0049-CFR
#

default ecs_root_user = null

aws_attribute_absence["ecs_root_user"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ContainerDefinitions
}

aws_issue["ecs_root_user"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.ContainerDefinitions[_].User) == "root"
}

ecs_root_user {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
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

ecs_root_user_err = "ECS taskdefinition attribute ContainerDefinitions missing in the resource" {
    aws_attribute_absence["ecs_root_user"]
}

ecs_root_user_metadata := {
    "Policy Code": "PR-AWS-0049-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition._x005F_x000D_ _x005F_x000D_ The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run_x005F_x000D_ _x005F_x000D_ Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}
