# Automated Vulnerability Scan result and Static Code Analysis for Google Cloud Platform (k8s-config-connector) (Nov 2021)

### https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/kcc/output11182021%20(Part1).md
### https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/kcc/output11182021%20(Part2).md

## Google KCC Services (Part 1)

Source Repository: https://github.com/GoogleCloudPlatform/k8s-config-connector

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1637184834855       |
| snapshot  | master-snapshot_gen |
| container | scenario-google-KCC |
| test      | master-test.json    |

## Results

### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT94                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['computedisk']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computedisk/regional-compute-disk/compute_v1beta1_computedisk_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT95                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['computedisk']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computedisk/regional-compute-disk/compute_v1beta1_computedisk_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **passed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT97                                                                                                                                       |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['computedisk']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computedisk/zonal-compute-disk/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT136                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computedisk']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeimage/image-from-existing-disk/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **passed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT139                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['computedisk']                                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computedisk_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT140                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['computedisk']                                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computedisk_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT146                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computedisk']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **passed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT151                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computedisk']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **failed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT172                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['computedisk']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancetemplate/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0001-KCC
Title: Disk CMEK Disabled\
Test Result: **passed**\
Description : Disks on this VM are not encrypted with CMEK or CSEC.\

#### Test Details
- eval: data.rule.disk_cmek_disabled
- id : PR-GCP-0001-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT243                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleKcc                                                                                                                          |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['computedisk']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computesnapshot/compute_v1beta1_computedisk.yaml'] |

- masterTestId: TEST_ComputeDisk
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeDisk.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0002-KCC
Title: Egress Deny Rule Not Set\
Test Result: **failed**\
Description : An egress deny rule is not set on a firewall.\

#### Test Details
- eval: data.rule.egress_deny_rule_not_set
- id : PR-GCP-0002-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0002-KCC
Title: Egress Deny Rule Not Set\
Test Result: **failed**\
Description : An egress deny rule is not set on a firewall.\

#### Test Details
- eval: data.rule.egress_deny_rule_not_set
- id : PR-GCP-0002-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0003-KCC
Title: Firewall Rule Logging Disabled\
Test Result: **failed**\
Description : Firewall rule logging is disabled.\

#### Test Details
- eval: data.rule.firewall_rule_logging_disabled
- id : PR-GCP-0003-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0003-KCC
Title: Firewall Rule Logging Disabled\
Test Result: **failed**\
Description : Firewall rule logging is disabled.\

#### Test Details
- eval: data.rule.firewall_rule_logging_disabled
- id : PR-GCP-0003-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0004-KCC
Title: OPEN CASSANDRA PORT\
Test Result: **passed**\
Description : A firewall is configured to have an open CASSANDRA port that allows generic access.\

#### Test Details
- eval: data.rule.open_cassandra_port
- id : PR-GCP-0004-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0004-KCC
Title: OPEN CASSANDRA PORT\
Test Result: **passed**\
Description : A firewall is configured to have an open CASSANDRA port that allows generic access.\

#### Test Details
- eval: data.rule.open_cassandra_port
- id : PR-GCP-0004-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0005-KCC
Title: Open Ciscosecure Websm Port\
Test Result: **passed**\
Description : A firewall is configured to have an open CISCOSECURE_WEBSM port that allows generic access.\

#### Test Details
- eval: data.rule.open_ciscosecure_websm_port
- id : PR-GCP-0005-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0005-KCC
Title: Open Ciscosecure Websm Port\
Test Result: **passed**\
Description : A firewall is configured to have an open CISCOSECURE_WEBSM port that allows generic access.\

#### Test Details
- eval: data.rule.open_ciscosecure_websm_port
- id : PR-GCP-0005-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0006-KCC
Title: Open Directory Services Port\
Test Result: **passed**\
Description : A firewall is configured to have an open DIRECTORY_SERVICES port that allows generic access.\

#### Test Details
- eval: data.rule.open_directory_services_port
- id : PR-GCP-0006-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0006-KCC
Title: Open Directory Services Port\
Test Result: **passed**\
Description : A firewall is configured to have an open DIRECTORY_SERVICES port that allows generic access.\

#### Test Details
- eval: data.rule.open_directory_services_port
- id : PR-GCP-0006-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0007-KCC
Title: Open DNS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open DNS port that allows generic access.\

#### Test Details
- eval: data.rule.open_dns_port
- id : PR-GCP-0007-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0007-KCC
Title: Open DNS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open DNS port that allows generic access.\

#### Test Details
- eval: data.rule.open_dns_port
- id : PR-GCP-0007-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0008-KCC
Title: Open DNS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open ELASTICSEARCH port that allows generic access.\

#### Test Details
- eval: data.rule.open_elasticsearch_port
- id : PR-GCP-0008-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0008-KCC
Title: Open DNS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open ELASTICSEARCH port that allows generic access.\

#### Test Details
- eval: data.rule.open_elasticsearch_port
- id : PR-GCP-0008-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0009-KCC
Title: Open Firewall\
Test Result: **failed**\
Description : A firewall is configured to be open to public access.\

#### Test Details
- eval: data.rule.open_firewall
- id : PR-GCP-0009-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0009-KCC
Title: Open Firewall\
Test Result: **failed**\
Description : A firewall is configured to be open to public access.\

#### Test Details
- eval: data.rule.open_firewall
- id : PR-GCP-0009-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0010-KCC
Title: Open FTP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open FTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_ftp_port
- id : PR-GCP-0010-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0010-KCC
Title: Open FTP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open FTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_ftp_port
- id : PR-GCP-0010-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0011-KCC
Title: Open HTTP Port\
Test Result: **failed**\
Description : A firewall is configured to have an open HTTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_http_port
- id : PR-GCP-0011-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0011-KCC
Title: Open HTTP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open HTTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_http_port
- id : PR-GCP-0011-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0012-KCC
Title: Open LDAP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open LDAP port that allows generic access.\

#### Test Details
- eval: data.rule.open_ldap_port
- id : PR-GCP-0012-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_11
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0012-KCC
Title: Open LDAP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open LDAP port that allows generic access.\

#### Test Details
- eval: data.rule.open_ldap_port
- id : PR-GCP-0012-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_11
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0013-KCC
Title: Open MEMCACHED Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MEMCACHED port that allows generic access.\

#### Test Details
- eval: data.rule.open_memcached_port
- id : PR-GCP-0013-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_12
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0013-KCC
Title: Open MEMCACHED Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MEMCACHED port that allows generic access.\

#### Test Details
- eval: data.rule.open_memcached_port
- id : PR-GCP-0013-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_12
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0014-KCC
Title: Open MONGODB Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MONGODB port that allows generic access.\

#### Test Details
- eval: data.rule.open_mongodb_port
- id : PR-GCP-0014-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_13
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0014-KCC
Title: Open MONGODB Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MONGODB port that allows generic access.\

#### Test Details
- eval: data.rule.open_mongodb_port
- id : PR-GCP-0014-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_13
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0015-KCC
Title: Open MySQL Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MySQL port that allows generic access.\

#### Test Details
- eval: data.rule.open_mysql_port
- id : PR-GCP-0015-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_14
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0015-KCC
Title: Open MySQL Port\
Test Result: **passed**\
Description : A firewall is configured to have an open MySQL port that allows generic access.\

#### Test Details
- eval: data.rule.open_mysql_port
- id : PR-GCP-0015-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_14
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0016-KCC
Title: Open NETBIOS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open NETBIOS port that allows generic access.\

#### Test Details
- eval: data.rule.open_netbios_port
- id : PR-GCP-0016-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_15
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0016-KCC
Title: Open NETBIOS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open NETBIOS port that allows generic access.\

#### Test Details
- eval: data.rule.open_netbios_port
- id : PR-GCP-0016-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_15
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0017-KCC
Title: Open ORACLEDB Port\
Test Result: **failed**\
Description : A firewall is configured to have an open ORACLEDB port that allows generic access.\

#### Test Details
- eval: data.rule.open_oracledb_port
- id : PR-GCP-0017-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_16
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0017-KCC
Title: Open ORACLEDB Port\
Test Result: **passed**\
Description : A firewall is configured to have an open ORACLEDB port that allows generic access.\

#### Test Details
- eval: data.rule.open_oracledb_port
- id : PR-GCP-0017-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_16
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0018-KCC
Title: Open POP3 Port\
Test Result: **passed**\
Description : A firewall is configured to have an open POP3 port that allows generic access.\

#### Test Details
- eval: data.rule.open_pop3_port
- id : PR-GCP-0018-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_17
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0018-KCC
Title: Open POP3 Port\
Test Result: **passed**\
Description : A firewall is configured to have an open POP3 port that allows generic access.\

#### Test Details
- eval: data.rule.open_pop3_port
- id : PR-GCP-0018-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_17
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0019-KCC
Title: Open POSTGRESQL Port\
Test Result: **passed**\
Description : A firewall is configured to have an open POSTGRESQL port that allows generic access.\

#### Test Details
- eval: data.rule.open_postgresql_port
- id : PR-GCP-0019-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_18
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0019-KCC
Title: Open POSTGRESQL Port\
Test Result: **passed**\
Description : A firewall is configured to have an open POSTGRESQL port that allows generic access.\

#### Test Details
- eval: data.rule.open_postgresql_port
- id : PR-GCP-0019-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_18
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0020-KCC
Title: Open RDP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open RDP port that allows generic access.\

#### Test Details
- eval: data.rule.open_rdp_port
- id : PR-GCP-0020-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_19
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0020-KCC
Title: Open RDP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open RDP port that allows generic access.\

#### Test Details
- eval: data.rule.open_rdp_port
- id : PR-GCP-0020-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_19
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0021-KCC
Title: Open REDIS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open REDIS port that allows generic access.\

#### Test Details
- eval: data.rule.open_redis_port
- id : PR-GCP-0021-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_20
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0021-KCC
Title: Open REDIS Port\
Test Result: **passed**\
Description : A firewall is configured to have an open REDIS port that allows generic access.\

#### Test Details
- eval: data.rule.open_redis_port
- id : PR-GCP-0021-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_20
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0022-KCC
Title: Open SMTP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open SMTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_smtp_port
- id : PR-GCP-0022-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_21
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0022-KCC
Title: Open SMTP Port\
Test Result: **passed**\
Description : A firewall is configured to have an open SMTP port that allows generic access.\

#### Test Details
- eval: data.rule.open_smtp_port
- id : PR-GCP-0022-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_21
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0023-KCC
Title: Open SSH Port\
Test Result: **passed**\
Description : A firewall is configured to have an open SSH port that allows generic access.\

#### Test Details
- eval: data.rule.open_ssh_port
- id : PR-GCP-0023-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_22
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0023-KCC
Title: Open SSH Port\
Test Result: **passed**\
Description : A firewall is configured to have an open SSH port that allows generic access.\

#### Test Details
- eval: data.rule.open_ssh_port
- id : PR-GCP-0023-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_22
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0024-KCC
Title: Open TELNET Port\
Test Result: **passed**\
Description : A firewall is configured to have an open TELNET port that allows generic access.\

#### Test Details
- eval: data.rule.open_telnet_port
- id : PR-GCP-0024-KCC

#### Snapshots
| Title         | Description                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT100                                                                                                                                               |
| structure     | filesystem                                                                                                                                                             |
| reference     | master                                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                            |
| type          | kcc                                                                                                                                                                    |
| region        |                                                                                                                                                                        |
| resourceTypes | ['computefirewall']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_23
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0024-KCC
Title: Open TELNET Port\
Test Result: **passed**\
Description : A firewall is configured to have an open TELNET port that allows generic access.\

#### Test Details
- eval: data.rule.open_telnet_port
- id : PR-GCP-0024-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT102                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computefirewall']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computefirewall.yaml'] |

- masterTestId: TEST_ComputeFirewall_23
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeFirewall.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0025-KCC
Title: Compute Secure Boot Disabled\
Test Result: **failed**\
Description : This Shielded VM does not have Secure Boot enabled.\

#### Test Details
- eval: data.rule.compute_secure_boot_disabled
- id : PR-GCP-0025-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0026-KCC
Title: Compute Serial Ports Enabled\
Test Result: **passed**\
Description : Serial ports are enabled for an instance, allowing connections to the instance's serial console.\

#### Test Details
- eval: data.rule.compute_serial_ports_enabled
- id : PR-GCP-0026-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **failed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0027-KCC
Title: IP Forwarding Enabled\
Test Result: **passed**\
Description : IP forwarding is enabled on instances.\

#### Test Details
- eval: data.rule.ip_forwarding_enabled
- id : PR-GCP-0027-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0028-KCC
Title: OS Login Disabled\
Test Result: **passed**\
Description : OS Login is disabled on this instance.\

#### Test Details
- eval: data.rule.os_login_disabled
- id : PR-GCP-0028-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0029-KCC
Title: Public IP Address\
Test Result: **passed**\
Description : An instance has a public IP address.\

#### Test Details
- eval: data.rule.public_ip_address
- id : PR-GCP-0029-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0030-KCC
Title: Shielded VM Disabled\
Test Result: **failed**\
Description : Shielded VM is disabled on this instance.\

#### Test Details
- eval: data.rule.shielded_vm_disabled
- id : PR-GCP-0030-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT141                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT147                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computeinstance']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT152                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['computeinstance']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT156                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT157                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computeinstance']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT266                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computeinstance']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computeinstance.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT271                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT272                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT273                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_2.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0031-KCC
Title: Org Policy Confidential VM Policy\
Test Result: **failed**\
Description : A Compute Engine resource is out of compliance with the constraints/compute.\

#### Test Details
- eval: data.rule.org_policy_confidential_vm_policy
- id : PR-GCP-0031-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT274                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computeinstance']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computeinstance_multiple_yaml_3.yaml'] |

- masterTestId: TEST_ComputeInstance_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT75                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeaddress/global-compute-address/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT77                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeaddress/regional-compute-address/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT86                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                                     |
| type          | kcc                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendservice/external-load-balancing-backend-service/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT93                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                                                             |
| type          | kcc                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendservice/internal-managed-load-balancing-backend-service/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT101                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computenetwork']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT103                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computenetwork']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT107                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleKcc                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['computenetwork']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewallpolicyrule/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT130                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeforwardingrule/regional-forwarding-rule/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT142                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT149                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT153                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT160                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['computenetwork']                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT165                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                       |
| resourceTypes | ['computenetwork']                                                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroupmanager/regional-compute-instance-group-manager/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT170                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                                        |
| type          | kcc                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroupmanager/zonal-compute-instance-group-manager/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT175                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancetemplate/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT179                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinterconnectattachment/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT181                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                            |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetwork/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT182                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkendpointgroup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT185                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkpeering/compute_v1beta1_computenetwork_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT186                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkpeering/compute_v1beta1_computenetwork_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT199                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleKcc                                                                                                                          |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['computenetwork']                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeroute/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT201                                                                                                                        |
| structure     | filesystem                                                                                                                                      |
| reference     | master                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                           |
| collection    | kcctemplate                                                                                                                                     |
| type          | kcc                                                                                                                                             |
| region        |                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouter/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT207                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouterinterface/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT213                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                                   |
| type          | kcc                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-for-all-subnets/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT216                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-for-list-of-subnets/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT221                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-with-manual-nat-ips/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT224                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouterpeer/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT232                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['computenetwork']                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeserviceattachment/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT250                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computesubnetwork/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT267                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT276                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT289                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetvpngateway/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT301                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computevpngateway/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT307                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                              |
| collection    | kcctemplate                                                                                                                                        |
| type          | kcc                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computevpntunnel/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT311                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['computenetwork']                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/configcontrollerinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT315                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                      |
| reference     | master                                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                     |
| type          | kcc                                                                                                                                                                             |
| region        |                                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT336                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['computenetwork']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/datafusioninstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                            |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsmanagedzone/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                    |
| structure     | filesystem                                                                                                                                  |
| reference     | master                                                                                                                                      |
| source        | gitConnectorGoogleKcc                                                                                                                       |
| collection    | kcctemplate                                                                                                                                 |
| type          | kcc                                                                                                                                         |
| region        |                                                                                                                                             |
| resourceTypes | ['computenetwork']                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnspolicy/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT371                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                             |
| collection    | kcctemplate                                                                                                                                       |
| type          | kcc                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/filestorebackup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT374                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/filestoreinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT480                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                              |
| collection    | kcctemplate                                                                                                                                        |
| type          | kcc                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/memcacheinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT527                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/servicenetworkingconnection/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0032-KCC
Title: Default Network\
Test Result: **passed**\
Description : The default network exists in a project.\

#### Test Details
- eval: data.rule.default_network
- id : PR-GCP-0032-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT543                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/private-ip-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT75                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeaddress/global-compute-address/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT77                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeaddress/regional-compute-address/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT86                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                                     |
| type          | kcc                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendservice/external-load-balancing-backend-service/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT93                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                                                             |
| type          | kcc                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendservice/internal-managed-load-balancing-backend-service/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT101                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['computenetwork']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/allow-rule-firewall/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT103                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                          |
| type          | kcc                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['computenetwork']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewall/deny-rule-firewall/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT107                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleKcc                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['computenetwork']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computefirewallpolicyrule/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT130                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeforwardingrule/regional-forwarding-rule/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT142                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT149                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/instance-from-template/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT153                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                               |
| type          | kcc                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/network-worker-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT160                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleKcc                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['computenetwork']                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT165                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                |
| source        | gitConnectorGoogleKcc                                                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                       |
| resourceTypes | ['computenetwork']                                                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroupmanager/regional-compute-instance-group-manager/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT170                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                                        |
| type          | kcc                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancegroupmanager/zonal-compute-instance-group-manager/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT175                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancetemplate/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT179                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinterconnectattachment/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT181                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                            |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetwork/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT182                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkendpointgroup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT185                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkpeering/compute_v1beta1_computenetwork_multiple_yaml_0.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT186                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                                             |
| type          | kcc                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkpeering/compute_v1beta1_computenetwork_multiple_yaml_1.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT199                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleKcc                                                                                                                          |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['computenetwork']                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeroute/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT201                                                                                                                        |
| structure     | filesystem                                                                                                                                      |
| reference     | master                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                           |
| collection    | kcctemplate                                                                                                                                     |
| type          | kcc                                                                                                                                             |
| region        |                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouter/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT207                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleKcc                                                                                                                                    |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['computenetwork']                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouterinterface/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT213                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                                   |
| type          | kcc                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-for-all-subnets/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT216                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-for-list-of-subnets/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT221                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-with-manual-nat-ips/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT224                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouterpeer/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT232                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['computenetwork']                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeserviceattachment/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT250                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computesubnetwork/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT267                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleKcc                                                                                                                                   |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['computenetwork']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT276                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT289                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleKcc                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['computenetwork']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetvpngateway/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT301                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computevpngateway/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT307                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                              |
| collection    | kcctemplate                                                                                                                                        |
| type          | kcc                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computevpntunnel/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT311                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleKcc                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['computenetwork']                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/configcontrollerinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT315                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                      |
| reference     | master                                                                                                                                                                          |
| source        | gitConnectorGoogleKcc                                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                     |
| type          | kcc                                                                                                                                                                             |
| region        |                                                                                                                                                                                 |
| resourceTypes | ['computenetwork']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT336                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleKcc                                                                                                                                |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['computenetwork']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/datafusioninstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleKcc                                                                                                                            |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['computenetwork']                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsmanagedzone/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                    |
| structure     | filesystem                                                                                                                                  |
| reference     | master                                                                                                                                      |
| source        | gitConnectorGoogleKcc                                                                                                                       |
| collection    | kcctemplate                                                                                                                                 |
| type          | kcc                                                                                                                                         |
| region        |                                                                                                                                             |
| resourceTypes | ['computenetwork']                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnspolicy/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT371                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                             |
| collection    | kcctemplate                                                                                                                                       |
| type          | kcc                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/filestorebackup/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT374                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorGoogleKcc                                                                                                                               |
| collection    | kcctemplate                                                                                                                                         |
| type          | kcc                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['computenetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/filestoreinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT480                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                              |
| collection    | kcctemplate                                                                                                                                        |
| type          | kcc                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['computenetwork']                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/memcacheinstance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT527                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleKcc                                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['computenetwork']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/servicenetworkingconnection/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0033-KCC
Title: Default Network\
Test Result: **passed**\
Description : A legacy network exists in a project.\

#### Test Details
- eval: data.rule.legacy_network
- id : PR-GCP-0033-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT543                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleKcc                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['computenetwork']                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/private-ip-instance/compute_v1beta1_computenetwork.yaml'] |

- masterTestId: TEST_ComputeNetwork_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeNetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0034-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : There are private subnetworks without access to Google public APIs.\

#### Test Details
- eval: data.rule.private_google_access_disabled
- id : PR-GCP-0034-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT78                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorGoogleKcc                                                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                                  |
| type          | kcc                                                                                                                                                                          |
| region        |                                                                                                                                                                              |
| resourceTypes | ['computesubnetwork']                                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeaddress/regional-compute-address/compute_v1beta1_computesubnetwork.yaml'] |

- masterTestId: TEST_ComputeSubnetwork
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeSubnetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0034-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : There are private subnetworks without access to Google public APIs.\

#### Test Details
- eval: data.rule.private_google_access_disabled
- id : PR-GCP-0034-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT89                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                             |
| source        | gitConnectorGoogleKcc                                                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                                        |
| type          | kcc                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                    |
| resourceTypes | ['computesubnetwork']                                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendservice/external-load-balancing-backend-service/compute_v1beta1_computesubnetwork.yaml'] |

- masterTestId: TEST_ComputeSubnetwork
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeSubnetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0034-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : There are private subnetworks without access to Google public APIs.\

#### Test Details
- eval: data.rule.private_google_access_disabled
- id : PR-GCP-0034-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT143                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                  |
| reference     | master                                                                                                                                                                      |
| source        | gitConnectorGoogleKcc                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                 |
| type          | kcc                                                                                                                                                                         |
| region        |                                                                                                                                                                             |
| resourceTypes | ['computesubnetwork']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstance/cloud-machine-instance/compute_v1beta1_computesubnetwork.yaml'] |

- masterTestId: TEST_ComputeSubnetwork
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ComputeSubnetwork.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------

