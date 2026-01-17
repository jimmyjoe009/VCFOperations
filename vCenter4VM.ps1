# Connect to Aria Operations using LDAP authentication
# Ignore invalid certificate errors

# Prompt for username and password
$username = Read-Host -Prompt "Enter your LDAP username"
$password = Read-Host -Prompt "Enter your LDAP password" -AsSecureString
$authSource = "my auth source"
$hostname = "myVCFOpshostname"

# Convert the secure string password to plain text for authentication (if needed)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Ignore SSL certificate errors
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Prepare the authentication body
$body = @{
    username = $username
    password = $UnsecurePassword
    authSource = $authSource
}

$uri = "https://$hostname/suite-api/api/auth/token/acquire"
$response = Invoke-RestMethod -Uri $uri -Method Post -Body ($body | ConvertTo-Json) -ContentType "application/json"


if ($response) {
#    Write-Host "Authentication successful. Full response type: $($response.GetType().FullName)"
    Write-Host "Authentication successful."
    if ($response -is [System.Xml.XmlDocument]) {
        $xmlString = $response.OuterXml
#        Write-Host "Raw XML response: $xmlString"
        $nsmgr = New-Object System.Xml.XmlNamespaceManager($response.NameTable)
        $nsmgr.AddNamespace("ops", "http://webservice.vmware.com/vRealizeOpsMgr/1.0/")
        $tokenNode = $response.SelectSingleNode("//ops:token", $nsmgr)
        if ($tokenNode) {
            $token = $tokenNode.InnerText
#            Write-Host "Extracted token: $token"
        } else {
            Write-Host "Could not find <ops:token> element in XML response."
            $token = $null
        }
    } else {
#        $response | ConvertTo-Json -Depth 10 | Write-Host
        $response | ConvertTo-Json -Depth 10
        $token = $response.token
#        Write-Host "Token value: $token"
    }

    # Prompt for VM name
    $vmName = Read-Host -Prompt "Enter the VM name to search for"


    # Query vROps for VM details using the correct endpoint and OpsToken
    $searchUri = "https://$hostname/suite-api/api/resources?name=$vmName&page=0&pageSize=1000&resourceKind=VirtualMachine&_no_links=true"
    $headers = @{
        "Authorization" = "OpsToken $token"
        "accept" = "application/json"
    }
    $lookupResponse = Invoke-RestMethod -Uri $searchUri -Headers $headers -Method Get -ErrorAction SilentlyContinue

    if ($lookupResponse -and $lookupResponse.resourceList.Count -gt 0) {
        $vm = $lookupResponse.resourceList[0]
        $resourceId = $vm.identifier
        if ($resourceId) {
#            Write-Host "ResourceId for VM '$vmName': $resourceId"
            $inventoryUrl = "https://$hostname/vcf-operations/ui/inventory;mode=hierarchy;resourceId=$resourceId"
#            Write-Host "Inventory UI URL for VM '$vmName': $inventoryUrl"

            # Recursively iterate through parent relationships to find the vCenter
            function Get-VCenterNameFromResourceId {
                param (
                    [string]$resourceId,
                    [hashtable]$headers
                )
                $parentUri = "https://$hostname/suite-api/api/resources/$resourceId/relationships?relationshipType=PARENT"
                $parentResponse = Invoke-RestMethod -Uri $parentUri -Headers $headers -Method Get -ErrorAction SilentlyContinue
#                Write-Host "Parent response for resourceId $($resourceId):"
#                $parentResponse | ConvertTo-Json -Depth 10 | Write-Host
                # Removed verbose parentResponse output
                if ($parentResponse -and $parentResponse.resourceList) {
                    foreach ($parent in $parentResponse.resourceList) {
                        if ($parent.resourceKey.resourceKindKey -eq "VM Entity Status") {
                            return $parent.identifier
                        }
                        elseif ($parent.identifier) {
                            # Recursively check the parent
                            $result = Get-VCenterNameFromResourceId -resourceId $parent.identifier -headers $headers
                            if ($result) { return $result }
                        }
                    }
                }
                return $null
            }

            $vcIdentifier = Get-VCenterNameFromResourceId -resourceId $resourceId -headers $headers
            if ($vcIdentifier) {
                #Write-Host "vCenter identifier associated with VM '$vmName': $vcIdentifier"
                # Final step: query the vCenter resource and output its VM name
                $vcResourceUri = "https://$hostname/suite-api/api/resources/$vcIdentifier"
                $vcResourceResponse = Invoke-RestMethod -Uri $vcResourceUri -Headers $headers -Method Get -ErrorAction SilentlyContinue
                if ($vcResourceResponse -and $vcResourceResponse.resourceKey -and $vcResourceResponse.resourceKey.name) {
                    Write-Host "Vcenter name for VM '$vmName': $($vcResourceResponse.resourceKey.name)"
                } else {
                    Write-Host "Could not retrieve VM name for vCenter identifier '$vcIdentifier'."
                }
            } else {
                Write-Host "Could not determine the vCenter identifier for VM '$vmName'."
            }
        } else {
            Write-Host "Could not determine the resourceId for VM '$vmName'."
        }
    } else {
        Write-Host "VM '$vmName' not found in Aria Operations."
    }
} else {
    Write-Host "Authentication failed."
}
