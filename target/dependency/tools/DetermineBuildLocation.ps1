Param( [Parameter(Mandatory=$True)][string]$POMPath, [Parameter(Mandatory=$True)][string]$groupId, [Parameter(Mandatory=$True)][string]$artifactId, [Parameter(Mandatory=$True)][string]$componentBuildStoreRoot, [Parameter(Mandatory=$True)][string]$outputPath )

#$POMPath = "C:\svn\Insight4.2\SummationProduct\Insight-4.2\pom.xml"
#$groupId = "ad.business-services"
#$artifactId = "ediscovery-services"
#$componentBuildStoreRoot = "\\buildstore\Products\WorkManager"
#$outputPath = "c:\output.txt"

$errorActionPreference = "stop"

Write-Host ("Input parameters" )
Write-Host( "POMPath = " + $POMPath )
Write-Host( "groupId = " + $groupId )
Write-Host( "artifactId = " + $artifactId )
Write-Host( "componentBuildStoreRoot = " + $componentBuildStoreRoot )
Write-Host( "outputPath = " + $outputPath )

# lookup the component version in the POM based on the component identifier
# append the component version and info to the componentBuildStoreRoot

if ( !(Test-Path $POMPath ) )
{
    throw( "Could not find POM at " + $POMPath )
}

if ( !(Test-Path $componentBuildStoreRoot) )
{
    throw( "Could not find componentBuildStoreRoot at " + $componentBuildStoreRoot )
}

[xml]$POM = Get-Content $POMPath

[bool]$dependencyFound = $False
$version

foreach( $POMdep in $POM.project.Dependencies.Dependency )
{
    if ( $POMdep.groupId -eq $groupId -and $POMdep.artifactId -eq $artifactId )
    {
        $dependencyFound = $True
        
        if ( $POMdep.Version.GetType().Name -eq "XmlElement" )
        {
            $version = $POMdep.Version.InnerText
        }
        else
        {
            $version = $POMdep.Version
        }
        
        Write-Host( [string]::Format( "Version for {0}:{1} is {2}", $groupId, $artifactId, $version ) )
    }
}

if ( !$dependencyFound )
{
    throw( [string]::Format( "Could not find dependency {0}:{1} in {2}", $groupId, $artifactId, $POMPath ) )
}

if ( [string]::IsNullOrEmpty( $version ) )
{
	throw( "Empty version string found!" )
}

if ( !($version -match "(\d+\.\d+\.\d+)\.(\d+.*)" ) )
{
    throw ( "Could not figure out version regex matching for " + $version + " in POM " + $POMPath )
}

Write-Host( "Regex match values" )
Write-Host( "[0]: " + $matches[0] )
Write-Host( "[1]: " + $matches[1] )
Write-Host( "[2]: " + $matches[2] )

$versionedSubDir = $matches[1].Replace( ".", "-" )

Write-Host( "versionedSubDir = " + $versionedSubDir )

$versionedPath = [System.IO.Path]::Combine( $componentBuildStoreRoot, $versionedSubDir )

if ( !(Test-Path $versionedPath ) )
{
    throw( "Could not find versioned subdirectory " + $versionedPath )
}

Write-Host( "versionedPath = " + $versionedPath )

$subDirRegex = [string]::Format( ".+{0}$", $matches[2] )

$finalDir = ( ls $versionedPath | where { $_.PsIsContainer -and $_.Name -match $subDirRegex } | sort LastWriteTime -descending | select -first 1 )

if ( $finalDir -eq $Null )
{
    throw( [string]::Format( "Could not find candidate directory in {0} - likely no matches for regex {1}", $versionedSubDir, $subdirRegex ) )
}

# have to ant-escape output strings
Set-Content $outputPath ([string]::Format( "BuildDirectory={0}", $finalDir.FullName.Replace( "\", "\\" ) ) )

Write-Host( [string]::Format( "BuildDirectory for {0}:{1} found at {2}, written to output file {3}", $groupId, $artifactId, $finalDir.FullName, $outputPath ) ) 



