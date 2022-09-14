



# Master Test ID: PR-AWS-CLD-SG-024


Master Snapshot Id: ['TEST_SG']

type: rego

rule: [file(securitygroup.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-SG-024|
|eval: |data.rule.port_9300|
|message: |data.rule.port_9300_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_SG_024.py|


severity: Medium

title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)

description: This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['security group']|



[file(securitygroup.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/securitygroup.rego
