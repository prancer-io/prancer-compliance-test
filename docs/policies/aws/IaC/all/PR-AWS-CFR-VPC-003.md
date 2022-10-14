



# Title: Ensure VPC endpoint service is configured for manual acceptance


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-VPC-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-VPC-003|
|eval|data.rule.vpc_endpoint_manual_acceptance|
|message|data.rule.vpc_endpoint_manual_acceptance_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpcendpointservice.html#cfn-ec2-vpcendpointservice-acceptancerequired' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_VPC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** AcceptanceRequired Indicates whether requests from service consumers to create an endpoint to your service must be accepted, we recommend you to enable this feature  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::vpcendpointservice']


[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego
