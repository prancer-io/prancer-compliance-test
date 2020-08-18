package rule

ec2 {
    resource := input.Resources[_]
    resource.Type="AWS::EC2::Instance"
    resource.Properties.InstanceType
    resource.Properties.InstanceType != null
    resource.Properties.InstanceType != ""
}

ec2 = false {
    resource := input.Resources[_]
    resource.Type="AWS::EC2::Instance"
    not resource.Properties.InstanceType
}

ec2_err = "Instance type does not set for EC2 Instance" {
    ec2 == false
}
