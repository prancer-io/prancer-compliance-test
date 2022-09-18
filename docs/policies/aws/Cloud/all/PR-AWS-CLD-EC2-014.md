



# Title: Ensure EC2 is communicating with other services outside VPC using VPC-endpoint.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC2-014

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC2_01', 'TEST_EC2_06']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC2-014|
|eval|data.rule.ec2_vpcendpoint|
|message|data.rule.ec2_vpcendpoint_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC2_014.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if a VPC endpoint is configured for EC2 to communicate to other AWs Services. Communication between AWS services by default traverses the internet to the service endpoints. This can be routed via the VPC by the usage of VPC endpoints.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'MAS TRM', 'MITRE ATT&CK', 'NZISM']|
|service|['ec2']|



[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
