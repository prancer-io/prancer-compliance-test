



# Title: AWS Lambda Function is not assigned to access within VPC


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-LMD-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-LMD-002|
|eval|data.rule.lambda_vpc|
|message|data.rule.lambda_vpc_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_LMD_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_lambda_function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego
