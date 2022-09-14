



# Master Test ID: PR-AWS-CLD-EC2-014


Master Snapshot Id: ['TEST_EC2_01', 'TEST_EC2_06']

type: rego

rule: [file(ec2.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EC2-014|
|eval: |data.rule.ec2_vpcendpoint|
|message: |data.rule.ec2_vpcendpoint_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EC2_014.py|


severity: Medium

title: Ensure EC2 is communicating with other services outside VPC using VPC-endpoint.

description: It checks if a VPC endpoint is configured for EC2 to communicate to other AWs Services. Communication between AWS services by default traverses the internet to the service endpoints. This can be routed via the VPC by the usage of VPC endpoints.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'MAS TRM', 'MITRE ATT&CK', 'NZISM']|
|service: |['ec2']|



[file(ec2.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ec2.rego
