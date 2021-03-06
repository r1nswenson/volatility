Param([Parameter(Mandatory=$True)][string]$domainUser,
      [Parameter(Mandatory=$True)][string]$domainPassword,
      [Parameter(Mandatory=$True)][string]$groupID,
      [Parameter(Mandatory=$True)][string]$artifactID,
      [Parameter(Mandatory=$True)][string]$codeline,
      [Parameter(Mandatory=$True)][string]$groupExclusions,
      [Parameter(Mandatory=$True)][string]$componentExclusions)
      
$errorActionPreference = "stop"

$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
 
if($netAssembly)
{
    $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
    $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")
 
    $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())
 
    if($instance)
    {
        $bindingFlags = "NonPublic","Instance"
        $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)
 
        if($useUnsafeHeaderParsingField)
        {
          $useUnsafeHeaderParsingField.SetValue($instance, $true)
        }
    }
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

function DownloadUrl( [string][Parameter(Mandatory=$True)]$url, [string][Parameter(Mandatory=$True)]$user, [string][Parameter(Mandatory=$True)]$password, [ref][Parameter(Mandatory=$True)]$output )
{
    $webClient = new-object System.Net.WebClient
    $webClient.Headers.Add("user-agent", "PowerShell Script")

    if ( ![string]::IsNullOrEmpty( $user ) )
    {
        $credentials = [string]::Format("{0}:{1}", $user, $password)
		$bytes = [System.Text.Encoding]::ASCII.GetBytes($credentials)
		$base64 = [System.Convert]::ToBase64String($bytes);
		$authorization = [string]::Concat("Basic ", $base64);
		$webClient.Headers.Add("Authorization", $authorization);
    }
    $output.Value = $webClient.DownloadString($url)
}

function Finish([string]$output, [string]$error)
{
    $output | Out-File output.txt
    if($error -ne "")
    {
        Throw($error)
    }
    exit
}

$output = ""
$clearPOMCacheUrl = [string]::Format("https://addev.adata.com/cgi-bin/components/update_pom_cache.pl")
$POMCacheCleared = ""
$attempts = 5
while($attempts -gt 0)
{
    DownloadUrl -url $clearPOMCacheUrl -user $domainUser -password $domainPassword -output ([ref]$POMCacheCleared)
    if($POMCacheCleared.Contains("Success"))
    {
        $output += "POM cache updated successfully`n"
        break
    }
    else
    {
        $attempts--
        if($attempts -gt 0)
        {
            $output += "Unable to update POM cache, retrying..." + $attempts + " remaining attempts`n"
        }
        Start-Sleep -s 15
    }
    if($attempts -eq 0)
    {
        Finish -output $output -error "Unable to update POM cache"
    }
}

$excludedGroups = ""
if($groupExclusions -ne "")
{
    $excludedGroups = "&exclude_groups="
    foreach($group in $groupExclusions.Split("+"))
    {
        $excludedGroups += $group + "%2C"
    }
    $excludedGroups = $excludedGroups.TrimEnd("%2C")
}

$excludedComponents = ""
if($componentExclusions -ne "")
{
    $excludedComponents = "&exclude_comps="
    foreach($comp in $componentExclusions.Split("+"))
    {
        $excludedComponents += $comp + "%2C"
    }
    $excludedComponents = $excludedComponents.TrimEnd("%2C")
}

if($codeline -ne "trunk")
{
    $codeline = "branch_" + $codeline
}

$checkVersionClashUrl = [string]::Format("https://addev.adata.com/cgi-bin-2/components/depgraph_generate.pl?view=deps&comp={0}%3A{1}&ver={2}&depth=inf&format=clash&follow_optional=on&all_mismatches_clash=1{3}{4}", $groupID, $artifactID, $codeline, $excludedGroups, $excludedComponents)
$output += $checkVersionClashUrl + "`n"

$versionClash = ""
$attempts = 5
while($attempts -gt 0)
{
    DownloadUrl -url $checkVersionClashUrl -user $domainUser -password $domainPassword -output ([ref]$versionClash)
    if($versionClash.StartsWith("1"))
    {
        $output += $versionClash
        $output += "Version clash detected`n"
        Finish -output $output -error "Version clash detected"
    }
    elseif($versionClash.StartsWith("0"))
    {
        $output += $versionClash
        $output += "No version clashes detected"
        Finish -output $output -error ""
    }
    else
    {
        $attempts--
        if($attempts -gt 0)
        {
            $output += "Unable to get a response from graph tool, retrying..." + $attempts + " remaining attempts`n"
        }
        if($attempts -eq 0)
        {
            Finish -output $output -error "Unable to get a response from graph tool"
        }
        Start-Sleep -s 15
    }
}