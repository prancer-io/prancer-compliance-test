package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html

#
# PR-AWS-CLD-ECS-001
#

default ecs_task_evelated = true

ecs_task_evelated = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    input.taskDefinition.containerDefinitions
    input.taskDefinition.containerDefinitions[j].privileged == true
}

ecs_task_evelated_err = "AWS ECS task definition elevated privileges enabled" {
    not ecs_task_evelated
}

ecs_task_evelated_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance. When the privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-CLD-ECS-002
#

default ecs_exec = true

ecs_exec = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    not input.taskDefinition.executionRoleArn
    not input.taskDefinition.taskRoleArn
}

ecs_exec = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    input.taskDefinition.executionRoleArn
    not startswith(lower(input.taskDefinition.executionRoleArn), "arn:aws:")
}

ecs_exec = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    input.taskDefinition.taskRoleArn
    not startswith(lower(input.taskDefinition.taskRoleArn), "arn:aws:")
}

ecs_exec_err = "AWS ECS/Fargate task definition execution IAM Role not found" {
    not ecs_exec
}

ecs_exec_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS/Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-CLD-ECS-003
#

default ecs_root_user = true

ecs_root_user = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(input.taskDefinition.containerDefinitions[j].user) == "root"
}

ecs_root_user_err = "AWS ECS/Fargate task definition root user found" {
    not ecs_root_user
}

ecs_root_user_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-CLD-ECS-004
#

default ecs_root_filesystem = true

ecs_root_filesystem = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    not container_definition.readonlyRootFilesystem
}

ecs_root_filesystem_err = "AWS ECS Task Definition readonlyRootFilesystem Not Enabled" {
    not ecs_root_filesystem
}

ecs_root_filesystem_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS Task Definition readonlyRootFilesystem Not Enabled",
    "Policy Description": "It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'containerDefinitions' template has 'readonlyRootFilesystem' and is set to 'true'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-CLD-ECS-005
#

default ecs_resource_limit = true

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    not input.taskDefinition.cpu
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(input.taskDefinition.cpu) == 0
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    not container_definition.cpu
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    to_number(container_definition.cpu) == 0
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    not input.taskDefinition.memory
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(input.taskDefinition.memory) == 0
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    not container_definition.memory
}

ecs_resource_limit = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    to_number(container_definition.memory) == 0
}

ecs_resource_limit_err = "AWS ECS task definition resource limits not set." {
    not ecs_resource_limit
}

ecs_resource_limit_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS task definition resource limits not set.",
    "Policy Description": "It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'cpu' or 'memory' exists and its value is not set to 0 under 'TaskDefinition' or 'containerDefinitions'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-CLD-ECS-006
#

default ecs_logging = true

ecs_logging = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    not container_definition.logConfiguration.logDriver
}

ecs_logging = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    count(container_definition.logConfiguration.logDriver) == 0
}

ecs_logging = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    container_definition.logConfiguration.logDriver == null
}

ecs_logging = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := input.taskDefinition.containerDefinitions[j]
    lower(container_definition.logConfiguration.logDriver) != "awslogs"
}


ecs_logging_err = "AWS ECS task definition logging not enabled. or only valid option for logDriver is 'awslogs'" {
    not ecs_logging
}

ecs_logging_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ECS task definition logging not enabled. or only valid option for logDriver is 'awslogs'",
    "Policy Description": "It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'logConfiguration' and 'logDriver' configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-CLD-ECS-007
#

default ecs_transit_enabled = true

ecs_transit_enabled = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := input.taskDefinition.volumes[j]
    not volume.efsVolumeConfiguration.transitEncryption
}

ecs_transit_enabled = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := input.taskDefinition.volumes[j]
    lower(volume.efsVolumeConfiguration.transitEncryption) != "enabled"
}

ecs_transit_enabled_err = "Ensure EFS volumes in ECS task definitions have encryption in transit enabled" {
    not ecs_transit_enabled
}

ecs_transit_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EFS volumes in ECS task definitions have encryption in transit enabled",
    "Policy Description": "ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-efsVolumeConfiguration.html#cfn-ecs-taskdefinition-efsVolumeConfiguration-transitEncryption"
}


#
# PR-AWS-CLD-ECS-008
#

default ecs_container_insight_enable = true

ecs_container_insight_enable = false {
    # lower(resource.Type) == "aws::ecs::cluster"
    clusters := input.clusters[i]
    settings := clusters.settings[j]
    lower(settings.name) == "containerinsights" 
    lower(settings.value) != "enabled"
}

ecs_container_insight_enable = false {
    # lower(resource.Type) == "aws::ecs::cluster"
    count([c | input.clusters[i].settings[j].name == "containerinsights" ; c:=1]) == 0
}

ecs_container_insight_enable = false {
    # lower(resource.Type) == "aws::ecs::cluster"
    count(input.settings) == 0
}

ecs_container_insight_enable_err = "Ensure container insights are enabled on ECS cluster" {
    not ecs_container_insight_enable
}

ecs_container_insight_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure container insights are enabled on ECS cluster",
    "Policy Description": "Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-cluster-settings.html#cfn-ecs-cluster-settings-name"
}


#
# PR-AWS-CLD-ECS-009
#

default ecs_enable_execute_command = true

ecs_enable_execute_command = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    services.enableExecuteCommand == true
}

ecs_enable_execute_command_err = "Ensure ECS Services and Task Set enableExecuteCommand property set to False" {
    not ecs_enable_execute_command
}

ecs_enable_execute_command_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ECS Services and Task Set enableExecuteCommand property set to False",
    "Policy Description": "If the enableExecuteCommand property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-enableExecuteCommand"
}


#
# PR-AWS-CLD-ECS-010
#

default ecs_assign_public_ip = true

ecs_assign_public_ip = false {
    # type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    lower(services.networkConfiguration.awsvpcConfiguration.assignPublicIp) == "enabled"
}

ecs_assign_public_ip_err = "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs" {
    not ecs_assign_public_ip
}

ecs_assign_public_ip_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs",
    "Policy Description": "Ensure that the ecs service and Task Set Network has set [assignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcConfiguration.html#cfn-ecs-service-awsvpcConfiguration-assignPublicIp"
}


#
# PR-AWS-CLD-ECS-011
#

default ecs_launch_type = true

ecs_launch_type = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    not services.launchType
}

ecs_launch_type = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    lower(input.launchType) != "fargate"
}

ecs_launch_type_err = "Ensure that ECS services and Task Sets are launched as Fargate type" {
    not ecs_launch_type
}

ecs_launch_type_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that ECS services and Task Sets are launched as Fargate type",
    "Policy Description": "Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-launchType"
}


#
# PR-AWS-CLD-ECS-012
#

default ecs_subnet = true

ecs_subnet = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    not services.networkConfiguration.awsvpcConfiguration.subnets
}

ecs_subnet = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    count(services.networkConfiguration.awsvpcConfiguration.subnets) == 0
}

ecs_subnet_err = "value(s) of subnets attached to aws ecs service or taskset awsvpcConfiguration resources are vended" {
    not ecs_subnet
}

ecs_subnet_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "value(s) of subnets attached to aws ecs service or taskset awsvpcConfiguration resources are vended",
    "Policy Description": "value(s) of subnets attached to aws ecs service or taskset awsvpcConfiguration resources are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcConfiguration.html#cfn-ecs-service-awsvpcConfiguration-subnets"
}


#
# PR-AWS-CLD-ECS-013
#

default ecs_security_group = true

ecs_security_group = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    not services.networkConfiguration.awsvpcConfiguration.securityGroups
}

ecs_security_group = false {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    # lower(resource.Type) == type[_]
    services := input.services[_]
    count(services.networkConfiguration.awsvpcConfiguration.securityGroups) == 0
}

ecs_security_group_err = "VPC configurations on ECS Services and TaskSets must use either vended security groups" {
    not ecs_security_group
}

ecs_security_group_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "VPC configurations on ECS Services and TaskSets must use either vended security groups",
    "Policy Description": "ECS Service and ECS TaskSet resources set a SecurityGroup in the awsvpcConfiguration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcConfiguration.html#cfn-ecs-service-awsvpcConfiguration-securityGroups"
}


#
# PR-AWS-CLD-ECS-014
#

default ecs_network_mode = true

ecs_network_mode = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    not input.taskDefinition.networkMode
}

ecs_network_mode = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    count(input.taskDefinition.networkMode) == 0
}

ecs_network_mode = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    input.taskDefinition.networkMode == null
}

ecs_network_mode = false {
    # lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(input.taskDefinition.networkMode) != "awsvpc"
}

ecs_network_mode_err = "Ensure that ECS Task Definition have their network mode property set to awsvpc" {
    not ecs_network_mode
}

ecs_network_mode_metadata := {
    "Policy Code": "PR-AWS-CLD-ECS-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that ECS Task Definition have their network mode property set to awsvpc",
    "Policy Description": "Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkMode"
}
