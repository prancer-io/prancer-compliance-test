



# Title: AWS Lambda Function is not assigned to access within VPC


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-LMD-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([lambda.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-LMD-002|
|eval|data.rule.lambda_vpc|
|message|data.rule.lambda_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_LMD_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::lambda::function']


[lambda.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego
