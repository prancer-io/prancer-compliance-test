package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html

#
# PR-AWS-CFR-ECS-001
#

default ecs_task_evelated = null

aws_bool_issue["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    resource.Properties.ContainerDefinitions[j].Privileged == true
}

source_path[{"ecs_task_evelated": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    resource.Properties.ContainerDefinitions[j].Privileged == true
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Privileged"]
        ],
    }
}

aws_issue["ecs_task_evelated"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    lower(resource.Properties.ContainerDefinitions[j].Privileged) == "true"
}

source_path[{"ecs_task_evelated": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ContainerDefinitions
    lower(resource.Properties.ContainerDefinitions[j].Privileged) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Privileged"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-ECS-001",
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
# PR-AWS-CFR-ECS-002
#

default ecs_exec = null

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ExecutionRoleArn
    not resource.Properties.TaskRoleArn
}

source_path[{"ecs_exec": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.ExecutionRoleArn
    not resource.Properties.TaskRoleArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TaskRoleArn"]
        ],
    }
}

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ExecutionRoleArn
    not startswith(lower(resource.Properties.ExecutionRoleArn), "arn:aws:")
}

source_path[{"ecs_exec": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.ExecutionRoleArn
    not startswith(lower(resource.Properties.ExecutionRoleArn), "arn:aws:")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ExecutionRoleArn"]
        ],
    }
}

aws_issue["ecs_exec"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.TaskRoleArn
    not startswith(lower(resource.Properties.TaskRoleArn), "arn:aws:")
}

source_path[{"ecs_exec": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.TaskRoleArn
    not startswith(lower(resource.Properties.TaskRoleArn), "arn:aws:")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TaskRoleArn"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-ECS-002",
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
# PR-AWS-CFR-ECS-003
#

default ecs_root_user = null

aws_issue["ecs_root_user"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.ContainerDefinitions[j].User) == "root"
}

source_path[{"ecs_root_user": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.ContainerDefinitions[j].User) == "root"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "User"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-ECS-003",
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
# PR-AWS-CFR-ECS-004
#

default ecs_root_filesystem = null

aws_bool_issue["ecs_root_filesystem"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.ReadonlyRootFilesystem
}

source_path[{"ecs_root_filesystem": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.ReadonlyRootFilesystem
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "ReadonlyRootFilesystem"]
        ],
    }
}

aws_issue["ecs_root_filesystem"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    lower(container_definition.ReadonlyRootFilesystem) == "false"
}

source_path[{"ecs_root_filesystem": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    lower(container_definition.ReadonlyRootFilesystem) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "ReadonlyRootFilesystem"]
        ],
    }
}

ecs_root_filesystem {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
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
    "Policy Code": "PR-AWS-CFR-ECS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS Task Definition readonlyRootFilesystem Not Enabled",
    "Policy Description": "It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'ContainerDefinitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-CFR-ECS-005
#

default ecs_resource_limit = null

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.Cpu
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.Cpu
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Cpu"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(resource.Properties.Cpu) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(resource.Properties.Cpu) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Cpu"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.Cpu
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.Cpu
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Cpu"]
        ],
    }
}


aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    to_number(container_definition.Cpu) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    to_number(container_definition.Cpu) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Cpu"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.Memory
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.Memory
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Memory"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(resource.Properties.Memory) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    to_number(resource.Properties.Memory) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Memory"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.Memory
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.Memory
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Memory"]
        ],
    }
}

aws_issue["ecs_resource_limit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    to_number(container_definition.Memory) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    to_number(container_definition.Memory) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "Memory"]
        ],
    }
}

ecs_resource_limit {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_resource_limit"]
}

ecs_resource_limit = false {
    aws_issue["ecs_resource_limit"]
}

ecs_resource_limit_err = "AWS ECS task definition resource limits not set." {
    aws_issue["ecs_resource_limit"]
}

ecs_resource_limit_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition resource limits not set.",
    "Policy Description": "It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-CFR-ECS-006
#

default ecs_logging = null

aws_issue["ecs_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.LogConfiguration.LogDriver
}

source_path[{"ecs_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    not container_definition.LogConfiguration.LogDriver
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "LogConfiguration", "LogDriver"]
        ],
    }
}

aws_issue["ecs_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    count(container_definition.LogConfiguration.LogDriver) == 0
}

source_path[{"ecs_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    count(container_definition.LogConfiguration.LogDriver) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "LogConfiguration", "LogDriver"]
        ],
    }
}

aws_issue["ecs_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    container_definition.LogConfiguration.LogDriver == null
}

source_path[{"ecs_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    container_definition.LogConfiguration.LogDriver == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "LogConfiguration", "LogDriver"]
        ],
    }
}

aws_issue["ecs_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    lower(container_definition.LogConfiguration.LogDriver) != "awslogs"
}

source_path[{"ecs_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    container_definition := resource.Properties.ContainerDefinitions[j]
    lower(container_definition.LogConfiguration.LogDriver) != "awslogs"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ContainerDefinitions", j, "LogConfiguration", "LogDriver"]
        ],
    }
}

ecs_logging {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_logging"]
}

ecs_logging = false {
    aws_issue["ecs_logging"]
}

ecs_logging_err = "AWS ECS task definition logging not enabled. or only valid option for LogDriver is 'awslogs'" {
    aws_issue["ecs_logging"]
}

ecs_logging_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS task definition logging not enabled. or only valid option for LogDriver is 'awslogs'",
    "Policy Description": "It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'LogConfiguration' and 'LogDriver' configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}


#
# PR-AWS-CFR-ECS-007
#

default ecs_transit_enabled = null

aws_issue["ecs_transit_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := resource.Properties.Volumes[j]
    not volume.EFSVolumeConfiguration.TransitEncryption
}

source_path[{"ecs_transit_enabled": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := resource.Properties.Volumes[j]
    not volume.EFSVolumeConfiguration.TransitEncryption
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Volumes", j, "EFSVolumeConfiguration", "TransitEncryption"]
        ],
    }
}

aws_issue["ecs_transit_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := resource.Properties.Volumes[j]
    lower(volume.EFSVolumeConfiguration.TransitEncryption) != "enabled"
}

source_path[{"ecs_transit_enabled": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    volume := resource.Properties.Volumes[j]
    lower(volume.EFSVolumeConfiguration.TransitEncryption) != "enabled"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Volumes", j, "EFSVolumeConfiguration", "TransitEncryption"]
        ],
    }
}

ecs_transit_enabled {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_transit_enabled"]
}

ecs_transit_enabled = false {
    aws_issue["ecs_transit_enabled"]
}


ecs_transit_enabled_err = "Ensure EFS volumes in ECS task definitions have encryption in transit enabled" {
    aws_issue["ecs_transit_enabled"]
}

ecs_transit_enabled_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EFS volumes in ECS task definitions have encryption in transit enabled",
    "Policy Description": "ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-efsvolumeconfiguration.html#cfn-ecs-taskdefinition-efsvolumeconfiguration-transitencryption"
}


#
# PR-AWS-CFR-ECS-008
#

default ecs_container_insight_enable = null

aws_issue["ecs_container_insight_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    ClusterSettings := resource.Properties.ClusterSettings[j]
    lower(ClusterSettings.Name) == "containerinsights" 
    lower(ClusterSettings.Value) != "enabled"
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    ClusterSettings := resource.Properties.ClusterSettings[j]
    lower(ClusterSettings.Name) == "containerinsights" 
    lower(ClusterSettings.Value) != "enabled"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ClusterSettings", j, "Value"]
        ],
    }
}

aws_issue["ecs_container_insight_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    count([c | resource.Properties.ClusterSettings[j].Name == "containerinsights" ; c:=1]) == 0
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    count([c | resource.Properties.ClusterSettings[j].Name == "containerinsights" ; c:=1]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ClusterSettings"]
        ],
    }
}

aws_issue["ecs_container_insight_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    count(resource.Properties.ClusterSettings) == 0
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::cluster"
    count(resource.Properties.ClusterSettings) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ClusterSettings"]
        ],
    }
}

ecs_container_insight_enable {
    lower(input.Resources[i].Type) == "aws::ecs::cluster"
    not aws_issue["ecs_container_insight_enable"]
}

ecs_container_insight_enable = false {
    aws_issue["ecs_container_insight_enable"]
}


ecs_container_insight_enable_err = "Ensure container insights are enabled on ECS cluster" {
    aws_issue["ecs_container_insight_enable"]
}

ecs_container_insight_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure container insights are enabled on ECS cluster",
    "Policy Description": "Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-cluster-clustersettings.html#cfn-ecs-cluster-clustersettings-name"
}


#
# PR-AWS-CFR-ECS-009
#

default ecs_enable_execute_command = null

aws_issue["ecs_enable_execute_command"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.EnableExecuteCommand) == "true"
}

source_path[{"ecs_enable_execute_command": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.EnableExecuteCommand) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EnableExecuteCommand"]
        ],
    }
}

aws_bool_issue["ecs_enable_execute_command"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    resource.Properties.EnableExecuteCommand == true
}

source_path[{"ecs_enable_execute_command": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    resource.Properties.EnableExecuteCommand == true
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EnableExecuteCommand"]
        ],
    }
}

ecs_enable_execute_command {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(input.Resources[i].Type) == type[_]
    not aws_issue["ecs_enable_execute_command"]
    not aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command = false {
    aws_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command = false {
    aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command_err = "Ensure ECS Services and Task Set EnableExecuteCommand property set to False" {
    aws_issue["ecs_enable_execute_command"]
} else = "Ensure ECS Services and Task Set EnableExecuteCommand property set to False" {
    aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECS Services and Task Set EnableExecuteCommand property set to False",
    "Policy Description": "If the EnableExecuteCommand property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-enableexecutecommand"
}


#
# PR-AWS-CFR-ECS-010
#

default ecs_assign_public_ip = null

aws_issue["ecs_assign_public_ip"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp) == "enabled"
}

source_path[{"ecs_assign_public_ip": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp) == "enabled"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkConfiguration", "AwsvpcConfiguration", "AssignPublicIp"]
        ],
    }
}

ecs_assign_public_ip {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    not aws_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip = false {
    aws_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip_err = "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs" {
    aws_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs",
    "Policy Description": "Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-assignpublicip"
}


#
# PR-AWS-CFR-ECS-011
#

default ecs_launch_type = null

aws_attribute_absence["ecs_launch_type"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.LaunchType
}

source_path[{"ecs_launch_type": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.LaunchType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LaunchType"]
        ],
    }
}

aws_issue["ecs_launch_type"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.LaunchType) != "fargate"
}

source_path[{"ecs_launch_type": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    lower(resource.Properties.LaunchType) != "fargate"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LaunchType"]
        ],
    }
}

ecs_launch_type {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(input.Resources[i].Type) == type[_]
    not aws_issue["ecs_launch_type"]
    not aws_attribute_absence["ecs_launch_type"]
}

ecs_launch_type = false {
    aws_issue["ecs_launch_type"]
}

ecs_launch_type = false {
    aws_attribute_absence["ecs_launch_type"]
}

ecs_launch_type_err = "Ensure that ECS services and Task Sets are launched as Fargate type" {
    aws_issue["ecs_launch_type"]
} else = "Ensure that ECS services and Task Sets are launched as Fargate type" {
    aws_attribute_absence["ecs_launch_type"]
}

ecs_launch_type_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ECS services and Task Sets are launched as Fargate type",
    "Policy Description": "Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html#cfn-ecs-service-launchtype"
}


#
# PR-AWS-CFR-ECS-012
#

default ecs_subnet = null

aws_attribute_absence["ecs_subnet"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.NetworkConfiguration.AwsvpcConfiguration.Subnets
}

source_path[{"ecs_subnet": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.NetworkConfiguration.AwsvpcConfiguration.Subnets
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkConfiguration", "AwsvpcConfiguration", "Subnets"]
        ],
    }
}

aws_issue["ecs_subnet"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    count(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.Subnets) == 0
}

source_path[{"ecs_subnet": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    count(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.Subnets) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkConfiguration", "AwsvpcConfiguration", "Subnets"]
        ],
    }
}

ecs_subnet {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    not aws_issue["ecs_subnet"]
    not aws_attribute_absence["ecs_subnet"]
}

ecs_subnet = false {
    aws_issue["ecs_subnet"]
}

ecs_subnet = false {
    aws_attribute_absence["ecs_subnet"]
}

ecs_subnet_err = "Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended" {
    aws_issue["ecs_subnet"]
} else = "Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended" {
    aws_attribute_absence["ecs_subnet"]
}

ecs_subnet_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended",
    "Policy Description": "Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-subnets"
}


#
# PR-AWS-CFR-ECS-013
#

default ecs_security_group = null

aws_attribute_absence["ecs_security_group"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups
}

source_path[{"ecs_security_group": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    not resource.Properties.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkConfiguration", "AwsvpcConfiguration", "SecurityGroups"]
        ],
    }
}

aws_issue["ecs_security_group"] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    count(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups) == 0
}

source_path[{"ecs_security_group": metadata}] {
    resource := input.Resources[i]
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    lower(resource.Type) == type[_]
    count(resource.Properties.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkConfiguration", "AwsvpcConfiguration", "SecurityGroups"]
        ],
    }
}

ecs_security_group {
    type = ["aws::ecs::service", "aws::ecs::taskset"]
    not aws_issue["ecs_security_group"]
    not aws_attribute_absence["ecs_security_group"]
}

ecs_security_group = false {
    aws_issue["ecs_security_group"]
}

ecs_security_group = false {
    aws_attribute_absence["ecs_security_group"]
}

ecs_security_group_err = "VPC configurations on ECS Services and TaskSets must use either vended security groups" {
    aws_issue["ecs_security_group"]
} else = "VPC configurations on ECS Services and TaskSets must use either vended security groups" {
    aws_attribute_absence["ecs_security_group"]
}

ecs_security_group_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "VPC configurations on ECS Services and TaskSets must use either vended security groups",
    "Policy Description": "ECS Service and ECS TaskSet resources set a SecurityGroup in the AwsvpcConfiguration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-service-awsvpcconfiguration.html#cfn-ecs-service-awsvpcconfiguration-securitygroups"
}


#
# PR-AWS-CFR-ECS-014
#

default ecs_network_mode = null

aws_issue["ecs_network_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.NetworkMode
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    not resource.Properties.NetworkMode
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkMode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    count(resource.Properties.NetworkMode) == 0
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    count(resource.Properties.NetworkMode) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkMode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.NetworkMode == null
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    resource.Properties.NetworkMode == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkMode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.NetworkMode) != "awsvpc"
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    lower(resource.Properties.NetworkMode) != "awsvpc"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkMode"]
        ],
    }
}

ecs_network_mode {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_network_mode"]
}

ecs_network_mode = false {
    aws_issue["ecs_network_mode"]
}

ecs_network_mode_err = "Ensure that ECS Task Definition have their network mode property set to awsvpc" {
    aws_issue["ecs_network_mode"]
}

ecs_network_mode_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ECS Task Definition have their network mode property set to awsvpc",
    "Policy Description": "Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkmode"
}


# #
# # PR-AWS-CFR-ECS-015
# #

# default ecs_network_mode = null

# allowed_regions = ["us-east-1"]

# image_location_regex = sprintf("^(\\${AWS::AccountId}|[0-9]{12})\\.dkr\\.ecr\\.(\\${AWS::Region}|%s)\\.\\${AWS::URLSuffix}/.*", [concat("|", allowed_regions)])

# valid_image_region_param(image){
# 	image["Fn::Join"][0] == ""
# 	array := image["Fn::Join"][1]
# 	array[0] == {"Ref": "AWS::AccountId"}
# 	array[1] == ".dkr.ecr."
# 	array[2] == {"Ref": "AWS::Region"}
# 	array[3] == "."
# 	array[4] == {"Ref": "AWS::URLSuffix"}
# 	regex.match("^/.*", array[5])
# }

# valid_image_region_string(image){
#     image["Fn::Join"][0] == ""
# 	array := image["Fn::Join"][1]
# 	array[0] == {"Ref": "AWS::AccountId"}
# 	startswith(array[1], ".dkr.ecr.")
# 	region := trim_suffix(trim_prefix(array[1], ".dkr.ecr."), ".")
# 	region == allowed_regions[_]
# 	array[2] == {"Ref": "AWS::URLSuffix"}
# 	regex.match("^/.*", array[3])
# }

# aws_issue["ecs_network_mode"] {
#     resource := input.Resources[i]
#     lower(resource.Type) == "aws::ecs::taskdefinition"
#     image := resource.Properties.ContainerDefinitions[j].Image
#     not regex.match(image_location_regex, image["Fn::Sub"])
#     not valid_image_region_param(image)
# 	not valid_image_region_string(image)
# }

# ecs_network_mode {
#     lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
#     not aws_issue["ecs_network_mode"]
# }

# ecs_network_mode = false {
#     aws_issue["ecs_network_mode"]
# }

# ecs_network_mode_err = "Ensure container images are deployed from ECR repository is in the service account's bootstrap stack." {
#     aws_issue["ecs_network_mode"]
# }

# ecs_network_mode_metadata := {
#     "Policy Code": "PR-AWS-CFR-ECS-015",
#     "Type": "IaC",
#     "Product": "AWS",
#     "Language": "AWS Cloud formation",
#     "Policy Title": "Ensure container images are deployed from ECR repository is in the service account's bootstrap stack.",
#     "Policy Description": "Ensure container images are deployed from ECR repository is in the service account's bootstrap stack.",
#     "Resource Type": "",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-networkmode"
# }


#
# PR-AWS-CFR-ECS-015
#

default ecs_fargate_task_definition_logging_is_enabled = null

aws_issue["ecs_fargate_task_definition_logging_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    not ContainerDefinition.LogConfiguration.LogDriver
}

aws_issue["ecs_fargate_task_definition_logging_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    contains(lower(ContainerDefinition.LogConfiguration.LogDriver), "false")
}

ecs_fargate_task_definition_logging_is_enabled {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_fargate_task_definition_logging_is_enabled"]
}

ecs_fargate_task_definition_logging_is_enabled = false {
    aws_issue["ecs_fargate_task_definition_logging_is_enabled"]
}

ecs_fargate_task_definition_logging_is_enabled_err = "AWS ECS - Ensure Fargate task definition logging is enabled." {
    aws_issue["ecs_fargate_task_definition_logging_is_enabled"]
}

ecs_fargate_task_definition_logging_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-015",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ECS - Ensure Fargate task definition logging is enabled.",
    "Policy Description": "It checks if the Fargate task definition created has an execution IAM role associated, the role defines the extent of access to other AWS Services.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#aws-resource-ecs-taskdefinition--examples"
}


#
# PR-AWS-CFR-ECS-016
#

default no_ecs_task_definition_empty_roles = null

aws_issue["no_ecs_task_definition_empty_roles"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    not ContainerDefinition.User
}

aws_issue["no_ecs_task_definition_empty_roles"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    ContainerDefinition.User == ""
}

aws_issue["no_ecs_task_definition_empty_roles"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    ContainerDefinition.User == null
}

aws_issue["no_ecs_task_definition_empty_roles"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    contains(ContainerDefinition.User, "*")
}

no_ecs_task_definition_empty_roles {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["no_ecs_task_definition_empty_roles"]
}

no_ecs_task_definition_empty_roles = false {
    aws_issue["no_ecs_task_definition_empty_roles"]
}

no_ecs_task_definition_empty_roles_err = "Ensure there are no undefined ECS task definition empty roles for ECS." {
    aws_issue["no_ecs_task_definition_empty_roles"]
}

no_ecs_task_definition_empty_roles_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure there are no undefined ECS task definition empty roles for ECS.",
    "Policy Description": "It checks if the ECS container has a role attached. The task execution role grants the Amazon ECS container and Fargate agents permission to make AWS API calls on your behalf. The task execution IAM role is required depending on the requirements of your task.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#aws-resource-ecs-taskdefinition--examples"
}


#
# PR-AWS-CFR-ECS-017
#

default ecs_log_driver = null

aws_issue["ecs_log_driver"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    not ContainerDefinition.LogConfiguration.LogDriver
}

aws_issue["ecs_log_driver"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    ContainerDefinition.LogConfiguration.LogDriver == ""
}

aws_issue["ecs_log_driver"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecs::taskdefinition"
    ContainerDefinition := resource.Properties.ContainerDefinitions[j]
    ContainerDefinition.LogConfiguration.LogDriver == null
}

ecs_log_driver {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["ecs_log_driver"]
}

ecs_log_driver = false {
    aws_issue["ecs_log_driver"]
}

ecs_log_driver_err = "Ensure that a log driver has been configured for each ECS task definition." {
    aws_issue["ecs_log_driver"]
}

ecs_log_driver_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that a log driver has been configured for each ECS task definition.",
    "Policy Description": "It checks if log information from the containers running on ECS are send out to CloudWatch logs for monitoring.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#aws-resource-ecs-taskdefinition--examples"
}
