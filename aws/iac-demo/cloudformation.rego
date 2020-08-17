git cpackage rule

# Load Balancer
test_load_balancer {
    resource := input.Resources[_]
    resource.Type="AWS::ElasticLoadBalancing::LoadBalancer"
    listener := resource.Properties.Listeners[_]
    listener.Protocol="HTTP"
    listener.LoadBalancerPort="80"
}

test_load_balancer = false {
    resource := input.Resources[_]
    resource.Type="AWS::ElasticLoadBalancing::LoadBalancer"
    listener := resource.Properties.Listeners[_]
    listener.Protocol="HTTP"
    listener.LoadBalancerPort!="80"
}

test_load_balancer_error = "Err: Load Balancer, LoadBalancerPort `80` does not set with `HTTP` protocol" {
    test_load_balancer == false
}

# DynamoDB
test_dynamo_db {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    resource.Properties.ProvisionedThroughput.WriteCapacityUnits="10"
    resource.Properties.ProvisionedThroughput.ReadCapacityUnits="5"
}

test_dynamo_db = false {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    resource.Properties.ProvisionedThroughput.WriteCapacityUnits!="10"
}

test_dynamo_db = false {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    resource.Properties.ProvisionedThroughput.ReadCapacityUnits!="5"
}

test_dynamo_db_error = "Err: DynamoDB, ProvisionedThroughput does set correctly. WriteCapacityUnits should be `10` and ReadCapacityUnits should be `5`." {
    test_dynamo_db == false
}


# EC2
test_ec2_instance {
    resource := input.Resources[_]
    resource.Type="AWS::EC2::Instance"
    resource.Properties.InstanceType
}

test_ec2_instance = false {
    resource := input.Resources[_]
    resource.Type="AWS::EC2::Instance"
    not resource.Properties.InstanceType
}

test_ec2_instance_error = "Err: EC2 instance type is not set" {
    test_ec2_instance == false
}


# Cluster
test_cluster {
    resource := input.Resources[_]
    resource.Type="AWS::EMR::Cluster"
    resource.Properties.Name
}

test_cluster = false {
    resource := input.Resources[_]
    resource.Type="AWS::EMR::Cluster"
    not resource.Properties.Name
}

test_cluster_error = "Err: Cluster name does not set" {
    test_cluster == false
}


# S3
test_S3_bucket {
    resource := input.Resources[_]
    resource.Type="AWS::S3::Bucket"
    resource.Properties.AccessControl != "PublicRead"
}

test_S3_bucket = false {
    resource := input.Resources[_]
    resource.Type="AWS::S3::Bucket"
    resource.Properties.AccessControl == "PublicRead"
}

test_S3_bucket_error = "Err: S3 Bucket access control is set to `PublicRead`" {
    test_S3_bucket == false
}


# SQS
test_SQS_Queue {
    resource := input.Resources[_]
    resource.Type="AWS::SQS::Queue"
    resource.Properties.ContentBasedDeduplication == "true"
}

test_SQS_Queue = false {
    resource := input.Resources[_]
    resource.Type="AWS::SQS::Queue"
    resource.Properties.ContentBasedDeduplication != "true"
}

test_SQS_Queue_error = "Err: SQS queue, `ContentBasedDeduplication` is set to `true`" {
    test_SQS_Queue == false
}

