



# Master Test ID: PR-AWS-CLD-LMD-002


Master Snapshot Id: ['TEST_LAMBDA']

type: rego

rule: [file(lambda.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-LMD-002|
|eval: |data.rule.lambda_vpc|
|message: |data.rule.lambda_vpc_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_LMD_002.py|


severity: Medium

title: AWS Lambda Function is not assigned to access within VPC

description: This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS']|
|service: |['lambda']|



[file(lambda.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/lambda.rego
