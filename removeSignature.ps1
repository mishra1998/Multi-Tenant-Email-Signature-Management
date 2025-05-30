param (
    [string]$email,
    [string]$organization
)

# Connect to Exchange Online
Connect-ExchangeOnline -AppId "9f6766f7-c9b6-46a0-a4c1-*******" -CertificateThumbprint "05693ECECED22B63154898E49A45*********" -Organization $organization;

# Remove existing rules for the sender
$existingRule = Get-TransportRule | Where-Object { $_.Name -like "*Signature for $email*" }
if ($existingRule) {
    $existingRule | Remove-TransportRule -Confirm:$false
    Write-Output "Signature removed for $email"
} else {
    Write-Output "No signature rule found for $email"
}
