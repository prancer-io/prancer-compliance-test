package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# Id: 47
#

default ecs_task_evelated = null

ecs_task_evelated {
    lower(input.Type) == "aws::ecs::taskdefinition"
    count([c | input.Properties.ContainerDefinitions[_].Privileged == false; c := 1]) ==
        count(input.Properties.ContainerDefinitions)
}

ecs_task_evelated = false {
    lower(input.Type) == "aws::ecs::taskdefinition"
    input.Properties.ContainerDefinitions[_].Privileged == true
}

ecs_task_evelated_err = "AWS ECS task definition elevated privileges enabled" {
    ecs_task_evelated == false
}

#
# Id: 48
#

default ecs_exec = null

ecs_exec {
    lower(input.Type) == "aws::ecs::taskdefinition"
    startswith(lower(input.Properties.ExecutionRoleArn), "arn:aws:iam")
}

ecs_exec = false {
    lower(input.Type) == "aws::ecs::taskdefinition"
    not startswith(lower(input.Properties.ExecutionRoleArn), "arn:aws:iam")
}

ecs_exec = false {
    lower(input.Type) == "aws::ecs::taskdefinition"
    not input.Properties.ExecutionRoleArn
}

ecs_exec_err = "AWS ECS/ Fargate task definition execution IAM Role not found" {
    ecs_exec == false
}

#
# Id: 49
#

default ecs_root_user = null

ecs_root_user {
    lower(input.Type) == "aws::ecs::taskdefinition"
    count([c | lower(input.Properties.ContainerDefinitions[_].User) == "root"; c := 1]) == 0
}

ecs_root_user = false {
    lower(input.Type) == "aws::ecs::taskdefinition"
    lower(input.Properties.ContainerDefinitions[_].User) == "root"
}

ecs_root_user_err = "AWS ECS/ Fargate task definition root user found" {
    ecs_root_user == false
}
