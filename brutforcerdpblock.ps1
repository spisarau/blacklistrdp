$ipdic = New-Object System.Collections.Generic.Dictionary[string`,int]
$rule=Get-NetFirewallRule -DisplayName "Blacklist connections to RDP" # Must be already created and deny all connections
$filter=$rule | Get-NetFirewallAddressFilter
$blacklist=$filter.RemoteAddress
$ipaddrstart="Сетевой адрес источника:"
$ipaddrend="Порт источника:"
Get-EventLog Security -InstanceId 4625 -After (Get-Date).AddMinutes(-5) -Before (Get-Date) |
foreach {
	$indexs=$PSItem.Message.IndexOf($ipaddrstart)
	$indexe=$PSItem.Message.IndexOf($ipaddrend)
 	$ip=$PSItem.Message.Substring($indexs,$indexe-$indexs).Replace($ipaddrstart,"").Trim();
 	if($ipdic[$ip] -eq $null){$ipdic.Add($ip,1)}else {$ipdic[$ip]++}
 
}
{};$ipdic | foreach {if(($_.Values -gt 10) -and ((write $_.Keys).Contains(".")))
{

(Set-NetFirewallAddressFilter -InputObject $filter -RemoteAddress @($blacklist+$_.Keys));
    $date=Get-Date
    $keys=(write $_.Keys)
Add-Content -Path .\log.txt -Value "$date $keys"
} }
