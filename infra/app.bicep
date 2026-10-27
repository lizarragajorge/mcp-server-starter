param location string
param appName string
param environmentName string
param registryName string
param identityName string
param imageTag string

@secure()
param apiKey string = ''

@allowed(['api_key', 'entra', 'broker'])
param authMode string = 'api_key'
param apiKeyHeader string = 'X-API-Key'
param entraTenantId string = ''
param entraAudience string = ''
param brokerClientId string = ''
@secure()
param brokerClientSecret string = ''
@secure()
param brokerSigningKey string = ''
@secure()
param brokerEncryptionKey string = ''
param brokerRedirectUris string = 'https://global.consent.azure-apim.net/redirect,https://global.consent.azure-apim.net/redirect/*'
@allowed([0, 1])
param minReplicas int = 0

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' existing = {
  name: environmentName
}
resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: registryName
}
resource pullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: identityName
}

resource brokerVnet 'Microsoft.Network/virtualNetworks@2024-05-01' = if (authMode == 'broker') {
  name: 'vnet-mcp-broker-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.98.0.0/16']
    }
    subnets: [
      {
        name: 'apps'
        properties: {
          addressPrefix: '10.98.0.0/23'
          delegations: [
            {
              name: 'container-apps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'endpoints'
        properties: {
          addressPrefix: '10.98.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}
resource brokerEnvironment 'Microsoft.App/managedEnvironments@2025-01-01' = if (authMode == 'broker') {
  name: '${environmentName}-broker'
  location: location
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: resourceId('Microsoft.Network/virtualNetworks/subnets', brokerVnet!.name, 'apps')
      internal: false
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
  dependsOn: [brokerVnet]
}

resource oauthStorage 'Microsoft.Storage/storageAccounts@2025-01-01' = if (authMode == 'broker') {
  name: 'stmcpoauth${uniqueString(resourceGroup().id)}'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
  }
}
resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2025-01-01' = if (authMode == 'broker') {
  parent: oauthStorage
  name: 'default'
}
resource oauthTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = if (authMode == 'broker') {
  parent: tableService
  name: 'oauthstate'
}
resource oauthRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (authMode == 'broker') {
  name: guid(oauthTable!.id, pullIdentity.id, 'OAuthTableData')
  scope: oauthTable
  properties: {
    principalId: pullIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
    )
  }
}

resource tableDns 'Microsoft.Network/privateDnsZones@2024-06-01' = if (authMode == 'broker') {
  name: 'privatelink.table.core.windows.net'
  location: 'global'
}
resource tableDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (authMode == 'broker') {
  parent: tableDns
  name: 'broker'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: brokerVnet!.id
    }
  }
}
resource tableEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = if (authMode == 'broker') {
  name: 'pe-mcp-oauth-table'
  location: location
  properties: {
    subnet: {
      id: resourceId('Microsoft.Network/virtualNetworks/subnets', brokerVnet!.name, 'endpoints')
    }
    privateLinkServiceConnections: [
      {
        name: 'oauth-table'
        properties: {
          privateLinkServiceId: oauthStorage!.id
          groupIds: ['table']
        }
      }
    ]
  }
  dependsOn: [brokerVnet]
}
resource tableDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = if (authMode == 'broker') {
  parent: tableEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'table'
        properties: {
          privateDnsZoneId: tableDns!.id
        }
      }
    ]
  }
}

var appDomain = authMode == 'broker'
  ? brokerEnvironment!.properties.defaultDomain
  : environment.properties.defaultDomain

resource app 'Microsoft.App/containerApps@2025-01-01' = {
  dependsOn: [oauthRole, tableDnsGroup, tableDnsLink]
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${pullIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: authMode == 'broker' ? brokerEnvironment!.id : environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
      }
      secrets: authMode == 'api_key' ? [
        {
          name: 'mcp-api-key'
          value: apiKey
        }
      ] : authMode == 'broker' ? [
        { name: 'oauth-client-secret', value: brokerClientSecret }
        { name: 'oauth-signing-key', value: brokerSigningKey }
        { name: 'oauth-encryption-key', value: brokerEncryptionKey }
      ] : []
      registries: [
        {
          server: registry.properties.loginServer
          identity: pullIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'catalog'
          image: '${registry.properties.loginServer}/${imageTag}'
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: concat([
            {
              name: 'MCP_AUTH_MODE'
              value: authMode
            }
            {
              name: 'MCP_API_KEY_HEADER'
              value: apiKeyHeader
            }
            {
              name: 'MCP_ALLOWED_HOSTS'
              value: '${appName}.${appDomain}'
            }
            {
              name: 'MCP_ENTRA_TENANT_ID'
              value: entraTenantId
            }
            {
              name: 'MCP_ENTRA_AUDIENCE'
              value: entraAudience
            }
            {
              name: 'MCP_RESOURCE_URL'
              value: 'https://${appName}.${appDomain}/mcp'
            }
          ], authMode == 'broker' ? [
            { name: 'MCP_BROKER_CLIENT_ID', value: brokerClientId }
            { name: 'MCP_BROKER_CLIENT_SECRET', secretRef: 'oauth-client-secret' }
            { name: 'MCP_BROKER_SIGNING_KEY', secretRef: 'oauth-signing-key' }
            { name: 'MCP_BROKER_ENCRYPTION_KEY', secretRef: 'oauth-encryption-key' }
            { name: 'MCP_BROKER_REDIRECT_URIS', value: brokerRedirectUris }
            { name: 'MCP_BROKER_TABLE_ENDPOINT', value: oauthStorage!.properties.primaryEndpoints.table }
            { name: 'MCP_BROKER_IDENTITY_CLIENT_ID', value: pullIdentity.properties.clientId }
          ] : [], authMode == 'api_key' ? [
            {
              name: 'MCP_API_KEY'
              secretRef: 'mcp-api-key'
            }
          ] : [])
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/health'
                port: 8000
              }
              periodSeconds: 5
              failureThreshold: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              periodSeconds: 10
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              periodSeconds: 30
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: authMode == 'broker' ? 1 : 3
        rules: [
          {
            name: 'http'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
}

output MCP_URL string = 'https://${app.properties.configuration.ingress.fqdn}/mcp'
