package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0047-TRF
#

default ecs_task_evelated = null

aws_bool_issue["ecs_task_evelated"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.container_definitions
    resource.properties.container_definitions[_].privileged == true
}

aws_issue["ecs_task_evelated"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.container_definitions
    lower(resource.properties.container_definitions[_].privileged) == "true"
}

ecs_task_evelated {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
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
    "Policy Code": "PR-AWS-0047-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance. When the privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

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

#
# PR-AWS-0049-TRF
#

default ecs_root_user = null

aws_issue["ecs_root_user"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    lower(resource.properties.container_definitions[_].user) == "root"
}

ecs_root_user {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_root_user"]
}

ecs_root_user = false {
    aws_issue["ecs_root_user"]
}

ecs_root_user_err = "AWS ECS/Fargate task definition root user found" {
    aws_issue["ecs_root_user"]
}

ecs_root_user_metadata := {
    "Policy Code": "PR-AWS-0049-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-0210-TRF
#

default ecs_root_filesystem = null

aws_bool_issue["ecs_root_filesystem"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    not container_definition.readonlyRootFilesystem
}

aws_issue["ecs_root_filesystem"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    lower(container_definition.readonlyRootFilesystem) == "false"
}

ecs_root_filesystem {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_root_filesystem"]
    not aws_bool_issue["ecs_root_filesystem"]
}

ecs_root_filesystem = false {
    aws_issue["ecs_root_filesystem"]
}

ecs_root_filesystem = false {
    aws_bool_issue["ecs_root_filesystem"]
}

ecs_root_filesystem_err = "AWS ECS Task Definition readonlyRootFilesystem Not Enabled" {
    aws_issue["ecs_root_filesystem"]
} else = "AWS ECS Task Definition readonlyRootFilesystem Not Enabled" {
    aws_bool_issue["ecs_root_filesystem"]
}

ecs_root_filesystem_metadata := {
    "Policy Code": "PR-AWS-0210-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS Task Definition readonlyRootFilesystem Not Enabled",
    "Policy Description": "It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'container_definitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-0211-TRF
#

default ecs_resource_limit = null

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.cpu
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.cpu == null
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.cpu) == 0
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    not container_definition.cpu
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    container_definition.cpu == null
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    to_number(container_definition.cpu) == 0
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.memory
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.memory == null
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.memory) == 0
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    not container_definition.memory
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    container_definition.memory == null
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    to_number(container_definition.memory) == 0
}


ecs_resource_limit {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_cpu_issue["ecs_resource_limit"]
    not aws_memory_issue["ecs_resource_limit"]
}

ecs_resource_limit = false {
    aws_cpu_issue["ecs_resource_limit"]
}

ecs_resource_limit = false {
    aws_memory_issue["ecs_resource_limit"]
}

ecs_resource_limit_err = "AWS ECS task definition resource limits not set." {
    aws_cpu_issue["ecs_resource_limit"]
} else = "AWS ECS task definition resource limits not set." {
    aws_memory_issue["ecs_resource_limit"]
}

ecs_resource_limit_metadata := {
    "Policy Code": "PR-AWS-0211-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition resource limits not set.",
    "Policy Description": "It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'cpu' or 'memory' exists and its value is not set to 0 under 'TaskDefinition' or 'container_definitions'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-0212-TRF
#

default ecs_logging = null

aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    not container_definition.logConfiguration.logDriver
}

aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    count(container_definition.logConfiguration.logDriver) == 0
}


aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[_]
    container_definition.logConfiguration.logDriver == null
}


ecs_logging {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_logging"]
}

ecs_logging = false {
    aws_issue["ecs_logging"]
}

ecs_logging_err = "AWS ECS task definition logging not enabled." {
    aws_issue["ecs_logging"]
}

ecs_logging_metadata := {
    "Policy Code": "PR-AWS-0212-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition logging not enabled.",
    "Policy Description": "It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'logConfiguration' and 'logDriver' configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-0254-TRF
#

default ecs_transit_enabled = null

aws_issue["ecs_transit_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.Volumes[_]
    not volume.efs_volume_configuration.transit_encryption
}

aws_issue["ecs_transit_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.Volumes[_]
    lower(volume.efs_volume_configuration.transit_encryption) != "enabled"
}

ecs_transit_enabled {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_transit_enabled"]
}

ecs_transit_enabled = false {
    aws_issue["ecs_transit_enabled"]
}


ecs_transit_enabled_err = "Ensure EFS volumes in ECS task definitions have encryption in transit enabled" {
    aws_issue["ecs_transit_enabled"]
}

ecs_transit_enabled_metadata := {
    "Policy Code": "PR-AWS-0254-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EFS volumes in ECS task definitions have encryption in transit enabled",
    "Policy Description": "ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-efsvolumeconfiguration.html#cfn-ecs-taskdefinition-efsvolumeconfiguration-transitencryption"
}
