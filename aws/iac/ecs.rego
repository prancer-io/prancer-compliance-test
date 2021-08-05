package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html

#
# PR-AWS-0047-CFR
#

default ecs_task_evelated = null

aws_bool_issue["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    resource.Properties.ContainerDefinitions[_].Privileged == true
}

aws_issue["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    lower(resource.Properties.ContainerDefinitions[_].Privileged) == "true"
}

ecs_task_evelated {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_task_evelated"]
    not aws_bool_issue["ecs_task_evelated"]
}

ecs_task_evelated = false {
    aws_issue["ecs_task_evelated"]
}

ecs_task_evelated = false {
    aws_bool_issue["ecs_task_evelated"]
}

ecs_task_evelated_err = "AWS ECS task definition elevated privileges enabled" {
    aws_issue["ecs_task_evelated"]
} else = "AWS ECS task definition elevated privileges enabled" {
    aws_bool_issue["ecs_task_evelated"]
}

ecs_task_evelated_metadata := {
    "Policy Code": "PR-AWS-0047-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance. When the Privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-0048-CFR
#

default ecs_exec = null

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ExecutionRoleArn
    not resource.Properties.TaskRoleArn
}

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ExecutionRoleArn
    not startswith(lower(resource.Properties.ExecutionRoleArn), "arn:aws:")
}

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.TaskRoleArn
    not startswith(lower(resource.Properties.TaskRoleArn), "arn:aws:")
}

ecs_exec {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_exec"]
}

ecs_exec = false {
    aws_issue["ecs_exec"]
}

ecs_exec_err = "AWS ECS/Fargate task definition execution IAM Role not found" {
    aws_issue["ecs_exec"]
}

ecs_exec_metadata := {
    "Policy Code": "PR-AWS-0048-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS/Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-0049-CFR
#

default ecs_root_user = null

aws_issue["ecs_root_user"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.ContainerDefinitions[_].User) == "root"
}

ecs_root_user {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_root_user"]
}

ecs_root_user = false {
    aws_issue["ecs_root_user"]
}

ecs_root_user_err = "AWS ECS/Fargate task definition root user found" {
    aws_issue["ecs_root_user"]
}

ecs_root_user_metadata := {
    "Policy Code": "PR-AWS-0049-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}
