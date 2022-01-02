# Automated Vulnerability Scan result and Static Code Analysis for Google Cloud Platform k8s-config-connector files (Dec 2021)

## All Services

#### Google KCC (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/kcc/Dec-2021/output12232021%20(Part1).md
#### Google KCC (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/kcc/Dec-2021/output12232021%20(Part2).md

## Google Cloud Platform k8s-config-connector Services (Part2)

Source Repository: https://github.com/GoogleCloudPlatform/k8s-config-connector

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1640235242343                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-google-k8sConfigConnector |
| test      | master-test.json                   |

## Results

### Test ID - PR-GCP-0034-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : There are private subnetworks without access to Google public APIs.\

#### Test Details
- eval: data.rule.private_google_access_disabled
- id : PR-GCP-0034-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT192                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['computesubnetwork']                                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeinstancetemplate/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT200                                                                                                                                         |
| structure     | filesystem                                                                                                                                                       |
| reference     | master                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                      |
| type          | kcc                                                                                                                                                              |
| region        |                                                                                                                                                                  |
| resourceTypes | ['computesubnetwork']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computenetworkendpointgroup/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT214                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['computesubnetwork']                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computepacketmirroring/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT241                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                           |
| reference     | master                                                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                 |
| collection    | kcctemplate                                                                                                                                                                          |
| type          | kcc                                                                                                                                                                                  |
| region        |                                                                                                                                                                                      |
| resourceTypes | ['computesubnetwork']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computerouternat/router-nat-for-list-of-subnets/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT256                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                                   |
| type          | kcc                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['computesubnetwork']                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeserviceattachment/compute_v1beta1_computesubnetwork_multiple_yaml_0.yaml'] |

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
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT257                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                                   |
| type          | kcc                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['computesubnetwork']                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeserviceattachment/compute_v1beta1_computesubnetwork_multiple_yaml_1.yaml'] |

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
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT258                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                                   |
| type          | kcc                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['computesubnetwork']                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeserviceattachment/compute_v1beta1_computesubnetwork_multiple_yaml_2.yaml'] |

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
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT275                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['computesubnetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computesubnetwork/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT292                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['computesubnetwork']                                                                                                                                      |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetinstance/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT301                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['computesubnetwork']                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computetargetpool/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT341                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                         |
| reference     | master                                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                                        |
| type          | kcc                                                                                                                                                                                |
| region        |                                                                                                                                                                                    |
| resourceTypes | ['computesubnetwork']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/compute_v1beta1_computesubnetwork.yaml'] |

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
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT625                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['computesubnetwork']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/vpcaccessconnector/subnet-connector/compute_v1beta1_computesubnetwork.yaml'] |

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


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0035-KCC
Title: Cluster Logging Disabled\
Test Result: **failed**\
Description : Logging isn't enabled for a GKE cluster.\

#### Test Details
- eval: data.rule.cluster_logging_disabled
- id : PR-GCP-0035-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0036-KCC
Title: Cluster Monitoring Disabled\
Test Result: **failed**\
Description : Monitoring is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.cluster_monitoring_disabled
- id : PR-GCP-0036-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0037-KCC
Title: COS Not Used\
Test Result: **passed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0037-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0038-KCC
Title: Legacy Authorization Enabled\
Test Result: **passed**\
Description : Legacy Authorization is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_authorization_enabled
- id : PR-GCP-0038-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **passed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0039-KCC
Title: Master Authorized Networks Disabled\
Test Result: **failed**\
Description : Master Authorized Networks is not enabled on GKE clusters.\

#### Test Details
- eval: data.rule.master_authorized_networks_disabled
- id : PR-GCP-0039-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0040-KCC
Title: Network Policy Disabled\
Test Result: **passed**\
Description : Network policy is disabled on GKE clusters.\

#### Test Details
- eval: data.rule.network_policy_disabled
- id : PR-GCP-0040-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_6
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0041-KCC
Title: Pod Security Policy Disabled\
Test Result: **passed**\
Description : PodSecurityPolicy is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.pod_security_policy_disabled
- id : PR-GCP-0041-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_7
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0042-KCC
Title: Private Cluster Disabled\
Test Result: **passed**\
Description : A GKE cluster has a Private cluster disabled.\

#### Test Details
- eval: data.rule.private_cluster_disabled
- id : PR-GCP-0042-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_8
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0043-KCC
Title: Web UI Enabled\
Test Result: **passed**\
Description : The GKE web UI (dashboard) is enabled.\

#### Test Details
- eval: data.rule.web_ui_enabled
- id : PR-GCP-0043-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_9
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **failed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT338                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['containercluster']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/autopilot-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **failed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT339                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                                           |
| type          | kcc                                                                                                                                                                                   |
| region        |                                                                                                                                                                                       |
| resourceTypes | ['containercluster']                                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/routes-based-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **passed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT342                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                                         |
| type          | kcc                                                                                                                                                                                 |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['containercluster']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containercluster/vpc-native-container-cluster/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **failed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT344                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['containercluster']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **passed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT409                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                        |
| reference     | master                                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                                       |
| type          | kcc                                                                                                                                                                               |
| region        |                                                                                                                                                                                   |
| resourceTypes | ['containercluster']                                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeature/multi-cluster-ingress-feature/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **passed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT421                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['containercluster']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubfeaturemembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0044-KCC
Title: Workload Identity Disabled\
Test Result: **passed**\
Description : Workload Identity is disabled on a GKE cluster.\

#### Test Details
- eval: data.rule.workload_identity_disabled
- id : PR-GCP-0044-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT429                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['containercluster']                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/gkehubmembership/container_v1beta1_containercluster.yaml'] |

- masterTestId: TEST_ContainerCluster_10
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerCluster.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0045-KCC
Title: Auto Repair Disabled\
Test Result: **passed**\
Description : A GKE cluster's auto repair feature, which keeps nodes in a healthy, running state, is disabled.\

#### Test Details
- eval: data.rule.auto_repair_disabled
- id : PR-GCP-0045-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                     |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['containernodepool']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containernodepool.yaml'] |

- masterTestId: TEST_ContainerNodePool_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0046-KCC
Title: Auto Upgrade Disabled\
Test Result: **passed**\
Description : A GKE cluster's auto upgrade feature, which keeps clusters and node pools on the latest stable version of Kubernetes, is disabled.\

#### Test Details
- eval: data.rule.auto_upgrade_disabled
- id : PR-GCP-0046-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                     |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['containernodepool']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containernodepool.yaml'] |

- masterTestId: TEST_ContainerNodePool_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0047-KCC
Title: COS Not Used\
Test Result: **failed**\
Description : Compute Engine VMs aren't using the Container-Optimized OS that is designed for running Docker containers on Google Cloud securely.\

#### Test Details
- eval: data.rule.cos_not_used
- id : PR-GCP-0047-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                     |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['containernodepool']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containernodepool.yaml'] |

- masterTestId: TEST_ContainerNodePool_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0048-KCC
Title: Legacy Metadata Enabled\
Test Result: **passed**\
Description : Legacy metadata is enabled on GKE clusters.\

#### Test Details
- eval: data.rule.legacy_metadata_enabled
- id : PR-GCP-0048-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT345                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                     |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['containernodepool']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/containernodepool/container_v1beta1_containernodepool.yaml'] |

- masterTestId: TEST_ContainerNodePool_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/ContainerNodePool.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT371                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                         |
| collection    | kcctemplate                                                                                                                                  |
| type          | kcc                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsmanagedzone/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT374                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-a-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT376                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                    |
| type          | kcc                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-aaaa-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT378                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-cname-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT380                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-mx-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT382                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-ns-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT384                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-srv-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT386                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-txt-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **failed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT388                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-dnskey-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **passed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT390                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-ds-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **passed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT392                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-ipsecvpnkey-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0049-KCC
Title: DNSSEC Disabled\
Test Result: **passed**\
Description : DNSSEC is disabled for Cloud DNS zones.\

#### Test Details
- eval: data.rule.dnssec_disabled
- id : PR-GCP-0049-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT394                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-sshfp-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT371                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                         |
| collection    | kcctemplate                                                                                                                                  |
| type          | kcc                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsmanagedzone/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT374                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-a-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT376                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                    |
| type          | kcc                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-aaaa-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT378                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-cname-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT380                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-mx-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT382                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-ns-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT384                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-srv-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT386                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                          |
| collection    | kcctemplate                                                                                                                                                   |
| type          | kcc                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dns-txt-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT388                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-dnskey-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT390                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-ds-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT392                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                               |
| reference     | master                                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                     |
| collection    | kcctemplate                                                                                                                                                              |
| type          | kcc                                                                                                                                                                      |
| region        |                                                                                                                                                                          |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-ipsecvpnkey-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0050-KCC
Title: RSASHA1 For Signing\
Test Result: **passed**\
Description : RSASHA1 is used for key signing in Cloud DNS zones.\

#### Test Details
- eval: data.rule.rsasha1_for_signing
- id : PR-GCP-0050-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT394                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['dnsmanagedzone']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dnsrecordset/dnssec-sshfp-record-set/dns_v1beta1_dnsmanagedzone.yaml'] |

- masterTestId: TEST_DNSManagedZone_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/DNSManagedZone.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0051-KCC
Title: Audit Logging Disabled\
Test Result: **failed**\
Description : Audit logging has been disabled for this resource.\

#### Test Details
- eval: data.rule.audit_logging_disabled
- id : PR-GCP-0051-KCC

#### Snapshots
| Title         | Description                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT444                                                                                                                                         |
| structure     | filesystem                                                                                                                                                       |
| reference     | master                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                      |
| type          | kcc                                                                                                                                                              |
| region        |                                                                                                                                                                  |
| resourceTypes | ['iampolicy']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/external-project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMpolicy_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0051-KCC
Title: Audit Logging Disabled\
Test Result: **failed**\
Description : Audit logging has been disabled for this resource.\

#### Test Details
- eval: data.rule.audit_logging_disabled
- id : PR-GCP-0051-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT447                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['iampolicy']                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/kms-policy-with-condition/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMpolicy_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0051-KCC
Title: Audit Logging Disabled\
Test Result: **passed**\
Description : Audit logging has been disabled for this resource.\

#### Test Details
- eval: data.rule.audit_logging_disabled
- id : PR-GCP-0051-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT450                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['iampolicy']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMpolicy_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0051-KCC
Title: Audit Logging Disabled\
Test Result: **failed**\
Description : Audit logging has been disabled for this resource.\

#### Test Details
- eval: data.rule.audit_logging_disabled
- id : PR-GCP-0051-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT453                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['iampolicy']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/pubsub-admin-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMpolicy_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0051-KCC
Title: Audit Logging Disabled\
Test Result: **failed**\
Description : Audit logging has been disabled for this resource.\

#### Test Details
- eval: data.rule.audit_logging_disabled
- id : PR-GCP-0051-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT456                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['iampolicy']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/workload-identity-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMpolicy_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0052-KCC
Title: Primitive Roles Used\
Test Result: **failed**\
Description : A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.\

#### Test Details
- eval: data.rule.primitive_roles_used
- id : PR-GCP-0052-KCC

#### Snapshots
| Title         | Description                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT444                                                                                                                                         |
| structure     | filesystem                                                                                                                                                       |
| reference     | master                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                      |
| type          | kcc                                                                                                                                                              |
| region        |                                                                                                                                                                  |
| resourceTypes | ['iampolicy']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/external-project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0052-KCC
Title: Primitive Roles Used\
Test Result: **passed**\
Description : A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.\

#### Test Details
- eval: data.rule.primitive_roles_used
- id : PR-GCP-0052-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT447                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['iampolicy']                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/kms-policy-with-condition/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0052-KCC
Title: Primitive Roles Used\
Test Result: **failed**\
Description : A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.\

#### Test Details
- eval: data.rule.primitive_roles_used
- id : PR-GCP-0052-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT450                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['iampolicy']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0052-KCC
Title: Primitive Roles Used\
Test Result: **passed**\
Description : A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.\

#### Test Details
- eval: data.rule.primitive_roles_used
- id : PR-GCP-0052-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT453                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['iampolicy']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/pubsub-admin-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0052-KCC
Title: Primitive Roles Used\
Test Result: **passed**\
Description : A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.\

#### Test Details
- eval: data.rule.primitive_roles_used
- id : PR-GCP-0052-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT456                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['iampolicy']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/workload-identity-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0053-KCC
Title: Redis Role Used On Org\
Test Result: **passed**\
Description : A Redis IAM role is assigned at the organization or folder level.\

#### Test Details
- eval: data.rule.redis_role_used_on_org
- id : PR-GCP-0053-KCC

#### Snapshots
| Title         | Description                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT444                                                                                                                                         |
| structure     | filesystem                                                                                                                                                       |
| reference     | master                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                      |
| type          | kcc                                                                                                                                                              |
| region        |                                                                                                                                                                  |
| resourceTypes | ['iampolicy']                                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/external-project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0053-KCC
Title: Redis Role Used On Org\
Test Result: **passed**\
Description : A Redis IAM role is assigned at the organization or folder level.\

#### Test Details
- eval: data.rule.redis_role_used_on_org
- id : PR-GCP-0053-KCC

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT447                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                         |
| collection    | kcctemplate                                                                                                                                                  |
| type          | kcc                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['iampolicy']                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/kms-policy-with-condition/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0053-KCC
Title: Redis Role Used On Org\
Test Result: **passed**\
Description : A Redis IAM role is assigned at the organization or folder level.\

#### Test Details
- eval: data.rule.redis_role_used_on_org
- id : PR-GCP-0053-KCC

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT450                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                    |
| collection    | kcctemplate                                                                                                                                             |
| type          | kcc                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['iampolicy']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/project-level-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0053-KCC
Title: Redis Role Used On Org\
Test Result: **passed**\
Description : A Redis IAM role is assigned at the organization or folder level.\

#### Test Details
- eval: data.rule.redis_role_used_on_org
- id : PR-GCP-0053-KCC

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT453                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                   |
| collection    | kcctemplate                                                                                                                                            |
| type          | kcc                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['iampolicy']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/pubsub-admin-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0053-KCC
Title: Redis Role Used On Org\
Test Result: **passed**\
Description : A Redis IAM role is assigned at the organization or folder level.\

#### Test Details
- eval: data.rule.redis_role_used_on_org
- id : PR-GCP-0053-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT456                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['iampolicy']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iampolicy/workload-identity-policy/iam_v1beta1_iampolicy.yaml'] |

- masterTestId: TEST_IAMPolicy_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMpolicy.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0054-KCC
Title: Service Account Key Not Rotated\
Test Result: **passed**\
Description : A service account key hasn't been rotated for more than 90 days\

#### Test Details
- eval: data.rule.service_account_key_not_rotated
- id : PR-GCP-0054-KCC

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT477                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                     |
| collection    | kcctemplate                                                                                                                                              |
| type          | kcc                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['iamserviceaccountkey']                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/iamserviceaccountkey/iam_v1beta1_iamserviceaccountkey.yaml'] |

- masterTestId: TEST_IAMServiceAccountKey
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/IAMServiceAccountKey.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0055-KCC
Title: KMS Key Not Rotated\
Test Result: **failed**\
Description : Rotation isn't configured on a Cloud KMS encryption key.\

#### Test Details
- eval: data.rule.kms_key_not_rotated
- id : PR-GCP-0055-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT20                                                                                                                                   |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                      |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['kmscryptokey']                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/copy-bigquery-job/kms_v1beta1_kmscryptokey.yaml'] |

- masterTestId: TEST_KMSCryptoKey
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/KMSCryptoKey.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0055-KCC
Title: KMS Key Not Rotated\
Test Result: **failed**\
Description : Rotation isn't configured on a Cloud KMS encryption key.\

#### Test Details
- eval: data.rule.kms_key_not_rotated
- id : PR-GCP-0055-KCC

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT492                                                                                                                 |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                     |
| collection    | kcctemplate                                                                                                                              |
| type          | kcc                                                                                                                                      |
| region        |                                                                                                                                          |
| resourceTypes | ['kmscryptokey']                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/kmscryptokey/kms_v1beta1_kmscryptokey.yaml'] |

- masterTestId: TEST_KMSCryptoKey
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/KMSCryptoKey.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT593                                                                                                               |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                   |
| collection    | kcctemplate                                                                                                                            |
| type          | kcc                                                                                                                                    |
| region        |                                                                                                                                        |
| resourceTypes | ['sqlinstance']                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqldatabase/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT594                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                      |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['sqlinstance']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **passed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT595                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                  |
| reference     | master                                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                                 |
| type          | kcc                                                                                                                                                                         |
| region        |                                                                                                                                                                             |
| resourceTypes | ['sqlinstance']                                                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **passed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT596                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT597                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT598                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                     |
| reference     | master                                                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                    |
| type          | kcc                                                                                                                                                                            |
| region        |                                                                                                                                                                                |
| resourceTypes | ['sqlinstance']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/postgres-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT602                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/private-ip-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT603                                                                                                              |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                  |
| collection    | kcctemplate                                                                                                                           |
| type          | kcc                                                                                                                                   |
| region        |                                                                                                                                       |
| resourceTypes | ['sqlinstance']                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlsslcert/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0056-KCC
Title: Auto Backup Disabled\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have automatic backups enabled.\

#### Test Details
- eval: data.rule.auto_backup_disabled
- id : PR-GCP-0056-KCC

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT606                                                                                                           |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                               |
| collection    | kcctemplate                                                                                                                        |
| type          | kcc                                                                                                                                |
| region        |                                                                                                                                    |
| resourceTypes | ['sqlinstance']                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqluser/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT593                                                                                                               |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                   |
| collection    | kcctemplate                                                                                                                            |
| type          | kcc                                                                                                                                    |
| region        |                                                                                                                                        |
| resourceTypes | ['sqlinstance']                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqldatabase/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT594                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                      |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['sqlinstance']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT595                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                  |
| reference     | master                                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                                 |
| type          | kcc                                                                                                                                                                         |
| region        |                                                                                                                                                                             |
| resourceTypes | ['sqlinstance']                                                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **passed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT596                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **passed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT597                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT598                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                     |
| reference     | master                                                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                    |
| type          | kcc                                                                                                                                                                            |
| region        |                                                                                                                                                                                |
| resourceTypes | ['sqlinstance']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/postgres-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT602                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/private-ip-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT603                                                                                                              |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                  |
| collection    | kcctemplate                                                                                                                           |
| type          | kcc                                                                                                                                   |
| region        |                                                                                                                                       |
| resourceTypes | ['sqlinstance']                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlsslcert/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0057-KCC
Title: SSL Not Enforced\
Test Result: **failed**\
Description : A Cloud SQL database instance doesn't require all incoming connections to use SSL.\

#### Test Details
- eval: data.rule.ssl_not_enforced
- id : PR-GCP-0057-KCC

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT606                                                                                                           |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                               |
| collection    | kcctemplate                                                                                                                        |
| type          | kcc                                                                                                                                |
| region        |                                                                                                                                    |
| resourceTypes | ['sqlinstance']                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqluser/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT593                                                                                                               |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                   |
| collection    | kcctemplate                                                                                                                            |
| type          | kcc                                                                                                                                    |
| region        |                                                                                                                                        |
| resourceTypes | ['sqlinstance']                                                                                                                        |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqldatabase/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT594                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                      |
| collection    | kcctemplate                                                                                                                                               |
| type          | kcc                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['sqlinstance']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT595                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                  |
| reference     | master                                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                                 |
| type          | kcc                                                                                                                                                                         |
| region        |                                                                                                                                                                             |
| resourceTypes | ['sqlinstance']                                                                                                                                                             |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT596                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_0.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT597                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                                |
| type          | kcc                                                                                                                                                                                        |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/mysql-sql-instance-with-replication/sql_v1beta1_sqlinstance_multiple_yaml_1.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT598                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                     |
| reference     | master                                                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                           |
| collection    | kcctemplate                                                                                                                                                                    |
| type          | kcc                                                                                                                                                                            |
| region        |                                                                                                                                                                                |
| resourceTypes | ['sqlinstance']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/postgres-sql-instance-high-availability/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT602                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                |
| type          | kcc                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['sqlinstance']                                                                                                                                            |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlinstance/private-ip-instance/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT603                                                                                                              |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                  |
| collection    | kcctemplate                                                                                                                           |
| type          | kcc                                                                                                                                   |
| region        |                                                                                                                                       |
| resourceTypes | ['sqlinstance']                                                                                                                       |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqlsslcert/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0058-KCC
Title: Sql No Root Password\
Test Result: **failed**\
Description : A Cloud SQL database doesn't have a password configured for the root account.\

#### Test Details
- eval: data.rule.sql_no_root_password
- id : PR-GCP-0058-KCC

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT606                                                                                                           |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                               |
| collection    | kcctemplate                                                                                                                        |
| type          | kcc                                                                                                                                |
| region        |                                                                                                                                    |
| resourceTypes | ['sqlinstance']                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/sqluser/sql_v1beta1_sqlinstance.yaml'] |

- masterTestId: TEST_SQLInstance_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/SQLInstance.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT25                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/extract-bigquery-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT96                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['storagebucket']                                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/basic-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT98                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/cdn-enabled-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT321                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['storagebucket']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeurlmap/global-compute-url-map/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                               |
| type          | kcc                                                                                                                                                                                       |
| region        |                                                                                                                                                                                           |
| resourceTypes | ['storagebucket']                                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowflextemplatejob/batch-dataflow-flex-template-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT355                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['storagebucket']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/batch-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT360                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/streaming-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT367                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                             |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataproccluster/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT505                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/logginglogsink/organization-sink/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT608                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                           |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['storagebucket']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT609                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['storagebucket']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucketaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT611                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['storagebucket']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagedefaultobjectaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT615                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                 |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['storagebucket']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagenotification/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT620                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_0.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0059-KCC
Title: Bucket CMEK Disabled\
Test Result: **failed**\
Description : A bucket is not encrypted with customer-managed encryption keys (CMEK).\

#### Test Details
- eval: data.rule.bucket_cmek_disabled
- id : PR-GCP-0059-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT621                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_1.yaml'] |

- masterTestId: TEST_StorageBucket_1
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT25                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/extract-bigquery-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT96                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['storagebucket']                                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/basic-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT98                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/cdn-enabled-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT321                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['storagebucket']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeurlmap/global-compute-url-map/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                               |
| type          | kcc                                                                                                                                                                                       |
| region        |                                                                                                                                                                                           |
| resourceTypes | ['storagebucket']                                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowflextemplatejob/batch-dataflow-flex-template-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT355                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['storagebucket']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/batch-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT360                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/streaming-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT367                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                             |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataproccluster/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT505                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/logginglogsink/organization-sink/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT608                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                           |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['storagebucket']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT609                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['storagebucket']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucketaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT611                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['storagebucket']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagedefaultobjectaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT615                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                 |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['storagebucket']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagenotification/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT620                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_0.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0060-KCC
Title: Bucket Policy Only Disabled\
Test Result: **failed**\
Description : Uniform bucket-level access, previously called Bucket Policy Only, isn't configured.\

#### Test Details
- eval: data.rule.bucket_policy_only_disabled
- id : PR-GCP-0060-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT621                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_1.yaml'] |

- masterTestId: TEST_StorageBucket_2
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT25                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/extract-bigquery-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT96                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['storagebucket']                                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/basic-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT98                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/cdn-enabled-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT321                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['storagebucket']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeurlmap/global-compute-url-map/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                               |
| type          | kcc                                                                                                                                                                                       |
| region        |                                                                                                                                                                                           |
| resourceTypes | ['storagebucket']                                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowflextemplatejob/batch-dataflow-flex-template-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT355                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['storagebucket']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/batch-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT360                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/streaming-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT367                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                             |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataproccluster/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT505                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/logginglogsink/organization-sink/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT608                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                           |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['storagebucket']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT609                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['storagebucket']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucketaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT611                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['storagebucket']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagedefaultobjectaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT615                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                 |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['storagebucket']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagenotification/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT620                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_0.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0061-KCC
Title: Bucket Logging Disabled\
Test Result: **failed**\
Description : There is a storage bucket without logging enabled.\

#### Test Details
- eval: data.rule.bucket_logging_disabled
- id : PR-GCP-0061-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT621                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_1.yaml'] |

- masterTestId: TEST_StorageBucket_3
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT25                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/extract-bigquery-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT96                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['storagebucket']                                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/basic-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT98                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/cdn-enabled-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT321                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['storagebucket']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeurlmap/global-compute-url-map/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                               |
| type          | kcc                                                                                                                                                                                       |
| region        |                                                                                                                                                                                           |
| resourceTypes | ['storagebucket']                                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowflextemplatejob/batch-dataflow-flex-template-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT355                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['storagebucket']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/batch-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT360                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/streaming-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT367                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                             |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataproccluster/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT505                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/logginglogsink/organization-sink/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT608                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                           |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['storagebucket']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT609                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['storagebucket']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucketaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT611                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['storagebucket']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagedefaultobjectaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT615                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                 |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['storagebucket']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagenotification/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT620                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_0.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0062-KCC
Title: Locked Retention Policy Not Set\
Test Result: **failed**\
Description : A locked retention policy is not set for logs.\

#### Test Details
- eval: data.rule.locked_retention_policy_not_set
- id : PR-GCP-0062-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT621                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_1.yaml'] |

- masterTestId: TEST_StorageBucket_4
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT25                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/bigqueryjob/extract-bigquery-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT96                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                       |
| collection    | kcctemplate                                                                                                                                                                |
| type          | kcc                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['storagebucket']                                                                                                                                                          |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/basic-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT98                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                             |
| collection    | kcctemplate                                                                                                                                                                      |
| type          | kcc                                                                                                                                                                              |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computebackendbucket/cdn-enabled-backend-bucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT321                                                                                                                                              |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                  |
| collection    | kcctemplate                                                                                                                                                           |
| type          | kcc                                                                                                                                                                   |
| region        |                                                                                                                                                                       |
| resourceTypes | ['storagebucket']                                                                                                                                                     |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/computeurlmap/global-compute-url-map/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT347                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                    |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                                      |
| collection    | kcctemplate                                                                                                                                                                               |
| type          | kcc                                                                                                                                                                                       |
| region        |                                                                                                                                                                                           |
| resourceTypes | ['storagebucket']                                                                                                                                                                         |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowflextemplatejob/batch-dataflow-flex-template-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT355                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                            |
| collection    | kcctemplate                                                                                                                                                     |
| type          | kcc                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['storagebucket']                                                                                                                                               |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/batch-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT360                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataflowjob/streaming-dataflow-job/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT367                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                             |
| collection    | kcctemplate                                                                                                                                      |
| type          | kcc                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['storagebucket']                                                                                                                                |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/dataproccluster/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT505                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                              |
| collection    | kcctemplate                                                                                                                                                       |
| type          | kcc                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['storagebucket']                                                                                                                                                 |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/logginglogsink/organization-sink/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **passed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT608                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                           |
| collection    | kcctemplate                                                                                                                                    |
| type          | kcc                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['storagebucket']                                                                                                                              |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucket/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT609                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                        |
| collection    | kcctemplate                                                                                                                                                 |
| type          | kcc                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['storagebucket']                                                                                                                                           |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagebucketaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT611                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                               |
| collection    | kcctemplate                                                                                                                                                        |
| type          | kcc                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['storagebucket']                                                                                                                                                  |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagedefaultobjectaccesscontrol/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT615                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                 |
| collection    | kcctemplate                                                                                                                                          |
| type          | kcc                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['storagebucket']                                                                                                                                    |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagenotification/storage_v1beta1_storagebucket.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT620                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_0.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------


### Test ID - PR-GCP-0063-KCC
Title: Object Versioning Disabled\
Test Result: **failed**\
Description : Object versioning isn't enabled on a storage bucket where sinks are configured.\

#### Test Details
- eval: data.rule.object_versioning_disabled
- id : PR-GCP-0063-KCC

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | KCC_TEMPLATE_SNAPSHOT621                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorGoogleK8sConfigConnector                                                                                                                                |
| collection    | kcctemplate                                                                                                                                                         |
| type          | kcc                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['storagebucket']                                                                                                                                                   |
| paths         | ['https://github.com/GoogleCloudPlatform/k8s-config-connector/tree/master/samples/resources/storagetransferjob/storage_v1beta1_storagebucket_multiple_yaml_1.yaml'] |

- masterTestId: TEST_StorageBucket_5
- masterSnapshotId: ['KCC_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/google/kcc/StorageBucket.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['kcc']       |
----------------------------------------------------------------

