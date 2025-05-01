param location string = resourceGroup().location
param ccePolicies object

resource attestation 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: deployment().name
  location: location
  properties: {
    osType: 'Linux'
    sku: 'Confidential'
    restartPolicy: 'Never'
    confidentialComputeProperties: {
      ccePolicy: ccePolicies.aci
    }
    containers: [
      {
        name: 'attestation'
        properties: {
        image: 'ghcr.io/domayre/confidential-server/attestation:latest'
          resources: {
            requests: {
              memoryInGB: 2
              cpu: 1
            }
          }
          command: [
            '/bin/bash'
            '-c'
            'get_snp_version && get_attestation_ccf "example-report-data"'
          ]
        }
      }
    ]
  }
}

output ids array = [
  attestation.id
]
