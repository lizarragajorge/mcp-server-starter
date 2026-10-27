targetScope = 'subscription'

@minLength(1)
@maxLength(32)
param environmentName string
param location string

resource rg 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-mcp-${environmentName}'
  location: location
  tags: {
    'azd-env-name': environmentName
    purpose: 'educational-mcp-demo'
  }
}

module hosting './hosting.bicep' = {
  name: 'catalog-hosting'
  scope: rg
  params: {
    location: location
  }
}

output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_CONTAINER_REGISTRY_NAME string = hosting.outputs.registryName
output AZURE_CONTAINER_ENVIRONMENT_NAME string = hosting.outputs.environmentName
output AZURE_CONTAINER_APP_NAME string = hosting.outputs.appName
output AZURE_PULL_IDENTITY_NAME string = hosting.outputs.identityName
