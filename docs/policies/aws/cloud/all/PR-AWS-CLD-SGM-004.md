



# Master Test ID: PR-AWS-CLD-SGM-004


***<font color="white">Master Snapshot Id:</font>*** ['TEST_SAGEMAKER']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sagemaker.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-SGM-004|
|eval|data.rule.sagemaker_vpc|
|message|data.rule.sagemaker_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_SGM_004.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** AWS SageMaker notebook instance is not placed in VPC

***<font color="white">Description:</font>*** This policy identifies SageMaker notebook instances that are not placed inside a VPC. It is recommended to place your SageMaker inside VPC so that VPC-only resources able to access your SageMaker data, which cannot be accessed outside a VPC network.

For more details:
https://docs.aws.amazon.com/sagemaker/latest/dg/process-vpc.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure network configuration', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:09.m', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1190 - Exploit Public-Facing Application', 'NIST CSF', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.5', 'NIST SP 800-172-3.13.4e', 'NZISM', 'New Zealand Information Security Manual (NZISM v3.4)-19.1', 'PCI DSS v3.2.1-1.3.6', 'PCI-DSS']|
|service|['sqs']|



[sagemaker.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/sagemaker.rego
