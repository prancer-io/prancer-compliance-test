package rule


#
# PR-AWS-TRF-ECS-001
#

default ecs_task_evelated = null

aws_bool_issue["ecs_task_evelated"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    container_definitions.privileged == true
}

source_path[{"ecs_task_evelated": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    container_definitions.privileged == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "privileged"]
        ],
    }
}

aws_issue["ecs_task_evelated"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    lower(container_definitions.privileged) == "true"
}

source_path[{"ecs_task_evelated": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    lower(container_definitions.privileged) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "privileged"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS task definition elevated privileges enabled",
    "Policy Description": "Ensure your ECS containers are not given elevated privileges on the host container instance. When the privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-002
#

default ecs_exec = null

aws_attribute_absence["ecs_exec"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.execution_role_arn
}

source_path[{"ecs_exec": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.execution_role_arn

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "execution_role_arn"]
        ],
    }
}

aws_issue["ecs_exec"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not startswith(lower(resource.properties.execution_role_arn), "arn:aws:iam")
}

source_path[{"ecs_exec": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not startswith(lower(resource.properties.execution_role_arn), "arn:aws:iam")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "execution_role_arn"]
        ],
    }
}

ecs_exec {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
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
    "Policy Code": "PR-AWS-TRF-ECS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS/Fargate task definition execution IAM Role not found",
    "Policy Description": "The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.",
    "Resource Type": "aws_ecs_task_definition",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-003
#

default ecs_root_user = null

aws_issue["ecs_root_user"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    lower(container_definitions.user) == "root"
}

source_path[{"ecs_root_user": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definitions := resource.properties.container_definitions[j]
    lower(container_definitions.user) == "root"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "user"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS/ Fargate task definition root user found",
    "Policy Description": "The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-004
#

default ecs_root_filesystem = null

aws_bool_issue["ecs_root_filesystem"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.readonlyRootFilesystem
}

source_path[{"ecs_root_filesystem": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.readonlyRootFilesystem

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "readonlyRootFilesystem"]
        ],
    }
}

aws_issue["ecs_root_filesystem"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    lower(container_definition.readonlyRootFilesystem) == "false"
}

source_path[{"ecs_root_filesystem": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    lower(container_definition.readonlyRootFilesystem) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "readonlyRootFilesystem"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS Task Definition readonlyRootFilesystem Not Enabled",
    "Policy Description": "It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'container_definitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}


#
# PR-AWS-TRF-ECS-005
#

default ecs_resource_limit = null

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.cpu
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.cpu

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cpu"]
        ],
    }
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.cpu == null
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.cpu == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cpu"]
        ],
    }
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.cpu) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.cpu) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cpu"]
        ],
    }
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.cpu
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.cpu

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "cpu"]
        ],
    }
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.cpu == null
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.cpu == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "cpu"]
        ],
    }
}

aws_cpu_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    to_number(container_definition.cpu) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    to_number(container_definition.cpu) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "cpu"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.memory
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.memory

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "memory"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.memory == null
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.memory == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "memory"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.memory) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    to_number(resource.properties.memory) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "memory"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.memory
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.memory

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "memory"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.memory == null
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.memory == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "memory"]
        ],
    }
}

aws_memory_issue["ecs_resource_limit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    to_number(container_definition.memory) == 0
}

source_path[{"ecs_resource_limit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    to_number(container_definition.memory) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "memory"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS task definition resource limits not set.",
    "Policy Description": "It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'cpu' or 'memory' exists and its value is not set to 0 under 'TaskDefinition' or 'container_definitions'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-006
#

default ecs_logging = null

aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.logConfiguration.logDriver
}

source_path[{"ecs_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    not container_definition.logConfiguration.logDriver

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "logConfiguration", "logDriver"]
        ],
    }
}

aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    count(container_definition.logConfiguration.logDriver) == 0
}

source_path[{"ecs_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    count(container_definition.logConfiguration.logDriver) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "logConfiguration", "logDriver"]
        ],
    }
}

aws_issue["ecs_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.logConfiguration.logDriver == null
}

source_path[{"ecs_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    container_definition := resource.properties.container_definitions[j]
    container_definition.logConfiguration.logDriver == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "container_definitions", j, "logConfiguration", "logDriver"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ECS task definition logging not enabled.",
    "Policy Description": "It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'logConfiguration' and 'logDriver' configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-007
#

default ecs_transit_enabled = null

aws_issue["ecs_transit_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.volume[j]
    efs_volume_configuration := volume.efs_volume_configuration[k]
    not efs_volume_configuration.transit_encryption
}

source_path[{"ecs_transit_enabled": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.volume[j]
    efs_volume_configuration := volume.efs_volume_configuration[k]
    not efs_volume_configuration.transit_encryption

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "volume", j, "efs_volume_configuration", k, "transit_encryption"]
        ],
    }
}

aws_issue["ecs_transit_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.volume[j]
    efs_volume_configuration := volume.efs_volume_configuration[k]
    lower(efs_volume_configuration.transit_encryption) != "enabled"
}

source_path[{"ecs_transit_enabled": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    volume := resource.properties.volume[j]
    efs_volume_configuration := volume.efs_volume_configuration[k]
    lower(efs_volume_configuration.transit_encryption) != "enabled"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "volume", j, "efs_volume_configuration", k, "transit_encryption"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-ECS-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure EFS volumes in ECS task definitions have encryption in transit enabled",
    "Policy Description": "ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-TRF-ECS-008
#

default ecs_container_insight_enable = null

aws_issue["ecs_container_insight_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    setting := resource.properties.setting[j]
    lower(setting.name) == "containerinsights" 
    lower(setting.value) != "enabled"
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    setting := resource.properties.setting[j]
    lower(setting.name) == "containerinsights" 
    lower(setting.value) != "enabled"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "setting", j, "value"]
        ],
    }
}

aws_issue["ecs_container_insight_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    count([c | resource.properties.setting[j].name == "containerinsights" ; c:=1]) == 0
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    count([c | resource.properties.setting[j].name == "containerinsights" ; c:=1]) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "setting"]
        ],
    }
}

aws_issue["ecs_container_insight_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    count(resource.properties.setting) == 0
}

source_path[{"ecs_container_insight_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    count(resource.properties.setting) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "setting"]
        ],
    }
}

ecs_container_insight_enable {
    lower(input.resources[i].type) == "aws_ecs_cluster"
    not aws_issue["ecs_container_insight_enable"]
}

ecs_container_insight_enable = false {
    aws_issue["ecs_container_insight_enable"]
}


ecs_container_insight_enable_err = "Ensure container insights are enabled on ECS cluster" {
    aws_issue["ecs_container_insight_enable"]
}

ecs_container_insight_enable_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure container insights are enabled on ECS cluster",
    "Policy Description": "Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster"
}

#
# PR-AWS-TRF-ECS-009
#

default ecs_enable_execute_command = null

aws_issue["ecs_enable_execute_command"] {
    resource := input.resources[i]
    
    lower(resource.type) == "aws_ecs_service"
    lower(resource.properties.enable_execute_command) == "true"
}

source_path[{"ecs_enable_execute_command": metadata}] {
    resource := input.resources[i]
    
    lower(resource.type) == "aws_ecs_service"
    lower(resource.properties.enable_execute_command) == "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "enable_execute_command"]
        ],
    }
}

aws_bool_issue["ecs_enable_execute_command"] {
    resource := input.resources[i]
    
    lower(resource.type) == "aws_ecs_service"
    resource.properties.enable_execute_command == true
}

source_path[{"ecs_enable_execute_command": metadata}] {
    resource := input.resources[i]
    
    lower(resource.type) == "aws_ecs_service"
    resource.properties.enable_execute_command == true
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "enable_execute_command"]
        ],
    }
}

ecs_enable_execute_command {
    lower(input.resources[i].type) == "aws_ecs_service"
    not aws_issue["ecs_enable_execute_command"]
    not aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command = false {
    aws_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command = false {
    aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command_err = "Ensure ECS Services and Task Set enable_execute_command property set to False" {
    aws_issue["ecs_enable_execute_command"]
} else = "Ensure ECS Services and Task Set enable_execute_command property set to False" {
    aws_bool_issue["ecs_enable_execute_command"]
}

ecs_enable_execute_command_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ECS Services and Task Set enable_execute_command property set to False",
    "Policy Description": "If the enable_execute_command property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#enable_execute_command"
}


#
# PR-AWS-TRF-ECS-010
#

default ecs_assign_public_ip = null

aws_issue["ecs_assign_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    lower(network_configuration.assign_public_ip) == "true"
}

source_path[{"ecs_assign_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    lower(network_configuration.assign_public_ip) == "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "assign_public_ip"]
        ],
    }
}

aws_bool_issue["ecs_assign_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    network_configuration.assign_public_ip == true
}

source_path[{"ecs_assign_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    network_configuration.assign_public_ip == true
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "assign_public_ip"]
        ],
    }
}
ecs_assign_public_ip {
    lower(input.resources[i].type) == "aws_ecs_service"
    not aws_issue["ecs_assign_public_ip"]
    not aws_bool_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip = false {
    aws_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip = false {
    aws_bool_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip_err = "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs" {
    aws_issue["ecs_assign_public_ip"]
} else = "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs" {
    aws_bool_issue["ecs_assign_public_ip"]
}

ecs_assign_public_ip_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs",
    "Policy Description": "Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration"
}


#
# PR-AWS-TRF-ECS-011
#

default ecs_launch_type = null

aws_attribute_absence["ecs_launch_type"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    not resource.properties.launch_type
}

source_path[{"ecs_launch_type": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    not resource.properties.launch_type
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "launch_type"]
        ],
    }
}

aws_issue["ecs_launch_type"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    lower(resource.properties.launch_type) != "fargate"
}

source_path[{"ecs_launch_type": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    lower(resource.properties.launch_type) != "fargate"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "launch_type"]
        ],
    }
}

ecs_launch_type {
    
    lower(input.resources[i].type) == "aws_ecs_service"
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
    "Policy Code": "PR-AWS-TRF-ECS-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS services and Task Sets are launched as Fargate type",
    "Policy Description": "Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#launch_type"
}


#
# PR-AWS-TRF-ECS-012
#

default ecs_subnet = null

aws_attribute_absence["ecs_subnet"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    not network_configuration.subnets
}

source_path[{"ecs_subnet": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    not network_configuration.subnets
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "subnets"]
        ],
    }
}

aws_issue["ecs_subnet"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    count(network_configuration.subnets) == 0
}

source_path[{"ecs_subnet": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    count(network_configuration.subnets) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "subnets"]
        ],
    }
}

ecs_subnet {
    lower(input.resources[i].type) == "aws_ecs_service"
    not aws_issue["ecs_subnet"]
    not aws_attribute_absence["ecs_subnet"]
}

ecs_subnet = false {
    aws_issue["ecs_subnet"]
}

ecs_subnet = false {
    aws_attribute_absence["ecs_subnet"]
}

ecs_subnet_err = "Value(s) of subnets attached to aws ecs service subnets are vended" {
    aws_issue["ecs_subnet"]
} else = "Value(s) of subnets attached to aws ecs service subnets are vended" {
    aws_attribute_absence["ecs_subnet"]
}

ecs_subnet_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Value(s) of subnets attached to aws ecs service subnets are vended",
    "Policy Description": "Value(s) of subnets attached to aws ecs service subnets are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration"
}


#
# PR-AWS-TRF-ECS-013
#

default ecs_security_group = null

aws_attribute_absence["ecs_security_group"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    not network_configuration.security_groups
}

source_path[{"ecs_security_group": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    not network_configuration.security_groups
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "security_groups"]
        ],
    }
}

aws_issue["ecs_security_group"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    count(network_configuration.security_groups) == 0
}

source_path[{"ecs_security_group": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_service"
    network_configuration := resource.properties.network_configuration[j]
    count(network_configuration.security_groups) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_configuration", j, "security_groups"]
        ],
    }
}

ecs_security_group {
    
    not aws_issue["ecs_security_group"]
    not aws_attribute_absence["ecs_security_group"]
}

ecs_security_group = false {
    aws_issue["ecs_security_group"]
}

ecs_security_group = false {
    aws_attribute_absence["ecs_security_group"]
}

ecs_security_group_err = "VPC configurations on ECS Services must use either vended security groups" {
    aws_issue["ecs_security_group"]
} else = "VPC configurations on ECS Services must use either vended security groups" {
    aws_attribute_absence["ecs_security_group"]
}

ecs_security_group_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "VPC configurations on ECS Services must use either vended security groups",
    "Policy Description": "ECS Service and ECS TaskSet resources set a SecurityGroup in the network_configuration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#network_configuration"
}


#
# PR-AWS-TRF-ECS-014
#

default ecs_network_mode = null

aws_issue["ecs_network_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.network_mode
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.network_mode
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_mode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    count(resource.properties.network_mode) == 0
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    count(resource.properties.network_mode) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_mode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.network_mode == null
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    resource.properties.network_mode == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_mode"]
        ],
    }
}

aws_issue["ecs_network_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    lower(resource.properties.network_mode) != "awsvpc"
}

source_path[{"ecs_network_mode": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    lower(resource.properties.network_mode) != "awsvpc"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_mode"]
        ],
    }
}

ecs_network_mode {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["ecs_network_mode"]
}

ecs_network_mode = false {
    aws_issue["ecs_network_mode"]
}

ecs_network_mode_err = "Ensure that ECS Task Definition have their network mode property set to awsvpc" {
    aws_issue["ecs_network_mode"]
}

ecs_network_mode_metadata := {
    "Policy Code": "PR-AWS-TRF-ECS-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS Task Definition have their network mode property set to awsvpc",
    "Policy Description": "Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#network_mode"
}
