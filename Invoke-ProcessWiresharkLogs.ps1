<#
	.SYNOPSIS
		Process Wireshark logs - Enrich DNS information with Virus Total domain categories
	
	.DESCRIPTION
		Processes the Wireshark logs stored locally from the Mirror port to
		build a timeline of destination lookups and output the results to a CSV
	
	.NOTES
	===========================================================================
	 Created on:   		08/04/2020
	 Created by:   		David Pitre
	 Filename:     		Invoke-ProcessWiresharkLogs.ps1
	 Version:		0.1
	 Classification:	Public
	===========================================================================

	.EXAMPLE
		PS C:\> ./Invoke-ProcessWiresharkLogs.ps1
	
	.LINK
		https://github.com/davidpitre/Invoke-ProcessWiresharkLogs

#>
$VerbosePreference:Continue
$CaptureLogsDirectory = Get-ChildItem -Path "C:\CaptureLogs" # Directory of pcap files from mirror port
$tmpDirectory = "C:\CaptureTmp" # Temporary location for processing data
[void](New-Item -path $tmpDirectory -ItemType "Directory" -Force)
[array]$Global:AllPackets = $null
[array]$Global:EnrichedDestinationData = $null
[string]$VTApiKey = "" # Register for a Virus Total community account @ https://www.virustotal.com/gui/join-us for access to an API key

function Invoke-ProcessWireSharkLogs
{
	param
	(
		[switch]$dnsquery
	)
	
	BEGIN
	{
		Write-Verbose -Message "Invoke-ProcessWireSharkLogs: Begin"
	}
	PROCESS
	{
		Write-Verbose -Message "Invoke-ProcessWireSharkLogs: Process"
		foreach ($CaptureFile in $CaptureLogsDirectory)
		{
			$capturefilepath = $CaptureFile.FullName
			switch ($dnsquery)
			{
				$true { [string]$TSharkArgs = " -r `"{0}`" -t ud -N mnNtdv -Tjson -e dns.qry.name -e frame.time -J `"TCP UDP`" -Y `"dns`"" -f $capturefilepath }
				$false { [string]$TSharkArgs = " -r `"{0}`" -t ud -N mnNtdv -Tjson -e ip.dst_host -e frame.time -J `"TCP`" -Y `"!(ip.dst == 192.168.10.0/24)`"" -f $capturefilepath }
			}
			try
			{
				start-process -WindowStyle Hidden -wait "C:\Program Files\Wireshark\tshark.exe" -argumentlist $TSharkArgs -RedirectStandardOutput ($tmpDirectory + "\" + $CaptureFile.Name)
			}
			catch
			{
				Write-Error -Message "Invoke-ProcessWireSharkLogs: TShark is not installed or the Capture file is in use"
			}
			$JsonPackets = Get-Content -Path ($tmpDirectory + "\" + $CaptureFile.Name) | convertfrom-json
			foreach ($Packet in $JsonPackets)
			{
				$FrameTimeReplace = ($packet._source.layers.'frame.time').Replace(",", "")
				$FrameTimeIndex = $FrameTimeReplace.Substring(0, $FrameTimeReplace.IndexOf('.'))
				$FrameTimeTrimSpace = $FrameTimeIndex.Replace("  ", " ")
				$ConvertedDatetime = [datetime]::ParseExact($FrameTimeTrimSpace, "MMM d yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
				$DestinationHost = [string]$packet._source.layers.'ip.dst_host'
				$Dnsqueryname = [string]$packet._source.layers.'dns.qry.name'
				
				if (!([string]::IsNullOrEmpty($DestinationHost)))
				{
					if (Check-DomainExclusion -domain $DestinationHost) { Continue }
				}
				if (!([string]::IsNullOrEmpty($Dnsqueryname)))
				{
					if (Check-DomainExclusion -domain $Dnsqueryname) { Continue }
				}
				
				$packetObject = New-Object -TypeName PSCustomObject
				$packetObject | Add-Member -membertype NoteProperty -Name "AccessTime" -Value ([datetime]$ConvertedDatetime)
				
				switch ($dnsquery)
				{
					$true { $packetObject | Add-Member -membertype NoteProperty -Name "Destination" -Value ([string]$Dnsqueryname) }
					$false { $packetObject | Add-Member -membertype NoteProperty -Name "Destination" -Value ([string]$DestinationHost) }
				}
				
				# Only include unique domains into the output
				if (!($Global:AllPackets.Destination -contains $packetObject.Destination))
				{
					$Global:AllPackets += $packetObject
				}
			}
			# Cleanup - delete the temporary output files
			Start-Sleep -Seconds 3
			Remove-Item ($tmpDirectory + "\" + $CaptureFile.Name) -Force
		}
		return $Global:AllPackets
	}
	END
	{
		Write-Verbose -Message "Invoke-ProcessWireSharkLogs: End"
	}
}

function Check-DomainExclusion
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$domain
	)
	BEGIN { }
	PROCESS
	{
		# List of common CDNs that we are not interested in
		if ($Domain -like "*.adobe.io") { return $true }
		if ($Domain -like "*.adobe.com") { return $true }
		if ($Domain -like "*.adobess*") { return $true }
		if ($Domain -like "*aaplimg.com") { return $true }
		if ($Domain -like "*224.0.0*") { return $true }
		if ($Domain -like "*akamai*") { return $true }
		if ($Domain -like "*amazonaws*") { return $true }
		if ($Domain -like "*apple.com") { return $true }
		if ($Domain -like "*apple-dns.net") { return $true }
		if ($Domain -like "*akadns.net") { return $true }
		if ($Domain -like "*adobejanus*") { return $true }
		if ($Domain -like "*mozaws.net") { return $true }
		if ($Domain -like "*apple-dns.net") { return $true }
		if ($Domain -like "*dropbox-dns.com") { return $true }
		if ($Domain -like "*.dropbox.com") { return $true }
		if ($Domain -like "*phicdn.net") { return $true }
		if ($Domain -like "*chicdn.net") { return $true }
		if ($Domain -like "*17.57.146*") { return $true }
		if ($Domain -like "*googleapis.com") { return $true }
		if ($Domain -like "*google.com") { return $true }
		if ($Domain -like "*msedge.net") { return $true }
		if ($Domain -like "*cloudfront.net") { return $true }
		if ($Domain -like "*llnwd.net") { return $true }
		if ($Domain -like "*mozgcp.net") { return $true }
		if ($Domain -like "*fastly.net") { return $true }
		if ($Domain -like "*typekit.com") { return $true }
		if ($Domain -like "*in-addr.arpa") { return $true }
		if ($Domain -like "*skype.com") { return $true }
		if ($Domain -like "*officeapps.live.com") { return $true }
		if ($Domain -like "*identrust.com") { return $true }
		if ($Domain -like "*.mozilla.*") { return $true }
		if ($Domain -like "*pinimg.com") { return $true }
		if ($Domain -like "*icloud.com") { return $true }
		if ($Domain -like "*adobelogin.com") { return $true }
		if ($Domain -like "*letsencrypt.org") { return $true }
		if ($Domain -like "*spccint.com") { return $true }
		if ($Domain -like "*mpulse.net") { return $true }
		if ($Domain -like "*symantecliveupdate.com") { return $true }
		if ($Domain -like "*mac-autofixer.com") { return $true }
		if ($Domain -like "*cdn.malwarecrusher.com") { return $true }
		if ($Domain -like "*digicert.com") { return $true }
		if ($Domain -like "*macinstl.com") { return $true }
		if ($Domain -like "*msg.databssint.com") { return $true }
		if ($Domain -like "*cdn.similarphotocleaner.com") { return $true }
		if ($Domain -like "*macinstl.com") { return $true }
		if ($Domain -like "*api.mapbox.com") { return $true }
		if ($Domain -like "*.gabmixer.com") { return $true }
		if ($Domain -like "*.ask.com") { return $true }
		if ($Domain -like "*google-analytics.com") { return $true }
		if ($Domain -like "local") { return $true }
		if ($Domain -like "*.adobesc.com") { return $true }
		if ($Domain -like "*.trustwave.com") { return $true }
		if ($Domain -like "*.ltwebstatic.com") { return $true }
		if ($Domain -like "*.symcd.com") { return $true }
		if ($Domain -like "*.symcd.com") { return $true }
		if ($Domain -like "*.rapidssl.com") { return $true }
		if ($Domain -like "*.usertrust.com") { return $true }
		if ($Domain -like "*.doubleclick.net") { return $true }
		if ($Domain -like "*.amazontrust.com") { return $true }
		if ($Domain -like "*.ads-twitter.com") { return $true }
		if ($Domain -like "**adservice.google.co.uk") { return $true }
		if ($Domain -like "*.sectigo.com") { return $true }
		if ($Domain -like "*.digitru.st") { return $true }
		if ($Domain -like "*.usertrust.com") { return $true }

		return $false
	}
	END { }
}

function Get-VTDomainCategories
{
	param
	(
		[string]$VTDomain
	)
	
	BEGIN
	{
		[string]$VTApiURL = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={0}&domain={1}" -f $VTApiKey, $VTDomain
	}
	PROCESS
	{
		Write-Host "Enriching Destination: "$VTDomain
		$VTReport = Invoke-RestMethod -Method 'GET' -Uri $VTApiURL
		return ($VTReport.categories -join ',')
	}
	END
	{
		Start-Sleep -Seconds 21
	}
}

function Invoke-EnrichDomainInfo
{
	BEGIN
	{
		$UniqueDNSCSV = Import-Csv -Path ([string]"C:\Source\uniquedns-{0}.csv" -f (Get-Date -Format "dMMyyyy"))
		[array]$EnrichedDestinationData = $null
	}
	PROCESS
	{
		foreach ($UniqueEntry in $UniqueDNSCSV)
		{
			$Catagories = Get-VTDomainCategories -VTDomain $UniqueEntry.Destination
			$csvObject = New-Object -TypeName PSCustomObject
			$csvObject | Add-Member -membertype NoteProperty -Name "AccessTime" -Value ([datetime]$UniqueEntry.AccessTime)
			$csvObject | Add-Member -membertype NoteProperty -Name "Destination" -Value ([string]$UniqueEntry.Destination)
			$csvObject | Add-Member -membertype NoteProperty -Name "Catagories" -Value ([string]$Catagories)
		    [array]$Global:EnrichedDestinationData += $csvObject
		}
		return [array]$Global:EnrichedDestinationData
	}
	END { }
}

Invoke-ProcessWireSharkLogs -dnsquery | Select-Object * -unique | Export-Csv -NoTypeInformation -NoClobber -Append `
																			 -Path ([string]"C:\Source\uniquedns-{0}.csv" -f (Get-Date -Format "dMMyyyy"))

Invoke-EnrichDomainInfo | Export-Csv -NoTypeInformation -NoClobber -Append -Path ([string]"C:\Source\uniquedns-enriched-{0}.csv" -f (Get-Date -Format "dMMyyyy"))
