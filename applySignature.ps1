param (
    [string]$email,
    [string]$organization,
    [string]$sanitizedHtml
)

# Decode the HTML
$decodedHtml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($sanitizedHtml))

# Connect to Exchange Online
Connect-ExchangeOnline -AppId "9f6766f7-c9b6-46a0-a4c1-*********" -CertificateThumbprint "05693ECECED22B63154898E49A45***********" -Organization $organization;

# Remove existing rules for the sender
$existingRule = Get-TransportRule | Where-Object { $_.Name -like "*Signature for $email*" }
if ($existingRule) {
    Remove-TransportRule -Identity $existingRule.Name -Confirm:$false;
}

# Apply new signature rule based on sender (From)
New-TransportRule -Name "Signature for $email" `
    -From "$email" `
    -ApplyHtmlDisclaimerText $decodedHtml `
    -ApplyHtmlDisclaimerLocation "Append" `
    -ApplyHtmlDisclaimerFallbackAction "Wrap";

# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false;
