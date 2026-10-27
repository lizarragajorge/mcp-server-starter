param location string
var suffix = uniqueString(resourceGroup().id)

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: 'cae-${suffix}'
  location: location
  properties: {
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' = {
  name: 'acrmcp${suffix}'
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource pullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-pull-${suffix}'
  location: location
}

resource pullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, pullIdentity.id, 'AcrPull')
  scope: registry
  properties: {
    principalId: pullIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d'
    )
  }
}

output registryName string = registry.name
output environmentName string = environment.name
output appName string = 'ca-catalog-${suffix}'
output identityName string = pullIdentity.name
