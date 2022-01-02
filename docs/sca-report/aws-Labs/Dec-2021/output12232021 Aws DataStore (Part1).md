# Automated Vulnerability Scan result and Static Code Analysis for Amazon Web Services Labs (Dec 2021)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Compute.md
#### DataStore (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20DataStore%20(Part1).md
#### DataStore (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20DataStore%20(Part2).md
#### Management: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part3).md
#### Networking (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part4).md
#### Networking (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part5).md
#### Networking (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part6).md
#### Networking (Part7): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part7).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Security.md

## AWS Data Store (Part1) Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1640425326411       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-CFR-S3-001

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-002
Title: AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_delete
- id : PR-AWS-CFR-S3-002

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-003
Title: AWS S3 Bucket has Global GET Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_get
- id : PR-AWS-CFR-S3-003

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-004
Title: AWS S3 Bucket has Global LIST Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_list
- id : PR-AWS-CFR-S3-004

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-005
Title: AWS S3 Bucket has Global PUT Permissions enabled via bucket policy\
Test Result: **passed**\
Description : This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.\

#### Test Details
- eval: data.rule.s3_acl_put
- id : PR-AWS-CFR-S3-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **failed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-CFR-S3-007

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **failed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **failed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-CFR-S3-008

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-009
Title: AWS S3 bucket not configured with secure data transport policy\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).\

#### Test Details
- eval: data.rule.s3_transport
- id : PR-AWS-CFR-S3-009

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-CFR-S3-010

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-CFR-S3-011

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: high

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-CFR-S3-012

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **failed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **failed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-CFR-S3-013

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::ec2::flowlog', 'aws::s3::bucket']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['ISO 27001']      |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::ec2::volume', 'aws::sns::topic', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::config::configrule', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::config::configurationrecorder'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::route53::recordset', 'aws::cloudfront::distribution', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-CFR-S3-014

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'custom::lambdatrig'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------

