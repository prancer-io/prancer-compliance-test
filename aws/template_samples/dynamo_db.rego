package rule

dynamo_db {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    resource.Properties.ProvisionedThroughput.ReadCapacityUnits
    resource.Properties.ProvisionedThroughput.WriteCapacityUnits
}

dynamo_db = false {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    not resource.Properties.ProvisionedThroughput.ReadCapacityUnits
}

dynamo_db = false {
    resource := input.Resources[_]
    resource.Type="AWS::DynamoDB::Table"
    not resource.Properties.ProvisionedThroughput.WriteCapacityUnits
}

dynamo_db_err = "ReadCapacityUnits or WriteCapacityUnits is not set for DynamoDB Tables." {
    dynamo_db == false
}
