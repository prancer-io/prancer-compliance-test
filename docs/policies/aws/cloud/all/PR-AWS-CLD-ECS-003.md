



# Master Test ID: PR-AWS-CLD-ECS-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECS_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECS-003|
|eval|data.rule.ecs_root_user|
|message|data.rule.ecs_root_user_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECS_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** AWS ECS/ Fargate task definition root user found

***<font color="white">Description:</font>*** The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 41", "CyberSecurity Law of the People's Republic of China-Article 43", "CyberSecurity Law of the People's Republic of China-Article 44", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MLPS', 'MLPS 2.0-8.1.5.1', 'NIST 800', 'NIST 800-53 Rev 5-Least Privilege', 'NIST 800-53 Rev4-AC-6', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-6.3', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['ecs']|



[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecs.rego
