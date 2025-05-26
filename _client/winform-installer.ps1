$scriptBasePath = [System.AppDomain]::CurrentDomain.BaseDirectory
if (-not $scriptBasePath -or $scriptBasePath -eq "")
{
	throw "Cannot determine the script directory. Make sure the EXE is not running in an unexpected context."
}
# This variable controls whether the application is allowed to exit.
# It is used in the form closing logic to minimize the form to the tray instead of exiting.
$script:allowExit = $true

# Consolidated Add-Type calls for required assemblies
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Function to check if running as admin
function Test-IsAdmin
{
	$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
	return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Get-CertificatePassword
{
	$passwordForm = New-Object System.Windows.Forms.Form
	$passwordForm.Text = "Certificate Password"
	$passwordForm.Size = New-Object System.Drawing.Size(300, 150)
	$passwordForm.StartPosition = "CenterScreen"
	
	$textBox = New-Object System.Windows.Forms.MaskedTextBox
	$textBox.PasswordChar = '*'
	$textBox.Location = New-Object System.Drawing.Point(10, 20)
	$textBox.Size = New-Object System.Drawing.Size(260, 20)
	$passwordForm.Controls.Add($textBox)
	
	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Point(75, 60)
	$okButton.Size = New-Object System.Drawing.Size(75, 23)
	$okButton.Text = "OK"
	$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$passwordForm.Controls.Add($okButton)
	
	$cancelButton = New-Object System.Windows.Forms.Button
	$cancelButton.Location = New-Object System.Drawing.Point(150, 60)
	$cancelButton.Size = New-Object System.Drawing.Size(75, 23)
	$cancelButton.Text = "Cancel"
	$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$passwordForm.Controls.Add($cancelButton)
	
	$passwordForm.AcceptButton = $okButton
	$passwordForm.CancelButton = $cancelButton
	
	$result = $passwordForm.ShowDialog()
	if ($result -eq [System.Windows.Forms.DialogResult]::OK)
	{
		return $textBox.Text
	}
	return $null
}

function Get-CACertificate
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$Url
	)
	
	$tempFile = [System.IO.Path]::GetTempFileName()
	try
	{
		Invoke-WebRequest -Uri $Url -OutFile $tempFile -UseBasicParsing
		$certContent = Get-Content $tempFile -Raw
		$base64 = $certContent -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
		while ($base64.Length % 4 -ne 0) { $base64 += '=' }
		$certBytes = [System.Convert]::FromBase64String($base64)
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$cert.Import($certBytes)
		return $cert
	}
	finally
	{
		if (Test-Path $tempFile)
		{
			Remove-Item -Path $tempFile -Force
		}
	}
}

# At the start of the script, check if running as admin and restart as user if needed
# At the start of the script, check if running as admin and restart as user if needed
if ($args -contains "-ElevatedAction")
{
    $elevatedActionIndex = $args.IndexOf("-ElevatedAction") + 1
    if ($elevatedActionIndex -lt $args.Length)
    {
        $elevatedAction = $args[$elevatedActionIndex]
        switch ($elevatedAction)
        {
            "IPSec service restart" {
                Write-Host "Performing elevated action: IPSec service restart"
                
                # Define all IPsec-related services
                $services = @("IKEEXT", "PolicyAgent", "BFE", "MpsSvc")
                
                # Stop services in reverse dependency order
                foreach ($svc in $services | Sort-Object -Descending) {
                    try {
                        $service = Get-Service -Name $svc -ErrorAction Stop
                        if ($service.Status -eq "Running") {
                            Stop-Service -Name $svc -Force -ErrorAction Stop
                            Write-Host "Stopped service: $svc"
                        }
                    }
                    catch {
                        Write-Host "Error stopping ${svc}: $($_.Exception.Message)"
                    }
                }
                
                # Wait to ensure services are fully stopped
                Start-Sleep -Seconds 3
                
                # Start services in dependency order
                foreach ($svc in $services) {
                    try {
                        Start-Service -Name $svc -ErrorAction Stop
                        Write-Host "Started service: $svc"
                    }
                    catch {
                        Write-Host "Error starting ${svc}: $($_.Exception.Message)"
                    }
                }
                
                # Service restart completed
                exit 0
            }
            # Other elevation actions can go here...
            default {
                Write-Error "Unknown elevated action: $elevatedAction"
                exit 1
            }
        }
    }
    else
    {
        Write-Error "No action specified for -ElevatedAction"
        exit 1
    }
}

$script:IsAdmin = Test-IsAdmin

# Only do this if we're running directly (not through the ElevatedAction path)
# and we want to ensure we're running as a normal user
if ($script:IsAdmin -and $args -notcontains "-AsAdmin")
{
    Write-Host "Running as admin, but admin not required for main UI. Restarting as normal user..."
    try
    {
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "powershell.exe"
        $processInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $processInfo.UseShellExecute = $true
        $processInfo.Verb = ""
        
        [System.Diagnostics.Process]::Start($processInfo)
        exit
    }
    catch
    {
        # If restart fails, continue as admin anyway
        Write-Host "Failed to restart as non-admin user: $_. Continuing as admin."
    }
}
function Request-AdminRights {
    param (
        [string]$Action
    )

    if (Test-IsAdmin) {
        Write-Host "Already running as admin."
        return $true
    }

    try {
        $statusLabel.Text = "Requesting elevation for $Action..."
        $form.Refresh()

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.Verb = "runas"
        $processInfo.FileName = "powershell.exe"

        # Get the absolute path to the script
        $scriptPath = Get-Location
        if ($MyInvocation.MyCommand.Path) {
            $scriptPath = $MyInvocation.MyCommand.Path
        }

        if (-not [System.IO.Path]::IsPathRooted($scriptPath)) {
            $scriptPath = [System.IO.Path]::GetFullPath($scriptPath)
        }

        # Build the arguments with proper quoting
        $processInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ElevatedAction `"$Action`""
        $processInfo.UseShellExecute = $true

        Write-Host "About to request elevation for: $Action"
        Write-Host "Script path: $scriptPath"
        Write-Host "Arguments: $($processInfo.Arguments)"

        $elevatedProcess = [System.Diagnostics.Process]::Start($processInfo)

        if ($null -eq $elevatedProcess) {
            $statusLabel.Text = "Failed to start elevated process"
            $form.Refresh()
            Write-Error "Failed to start elevated process"
            Start-Sleep -Seconds 2
            return $false
        }

        $elevatedProcess.WaitForExit()
        $exitCode = $elevatedProcess.ExitCode

        Write-Host "Process exited with code: $exitCode"

        # Very important: For IPSec services restart specifically,
        # always return success if the process completed at all
        if ($Action -eq "IPSec service restart") {
            return $true
        }

        return ($exitCode -eq 0)
    }
    catch {
        $statusLabel.Text = "Failed to elevate: $_"
        $form.Refresh()
        Write-Error "Failed to elevate: $_"
        Start-Sleep -Seconds 2
        return $false
    }
}

function Import-UserCertificate
{
	param (
		[switch]$SkipCAExtraction
	)
	
	$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	$openFileDialog.Filter = "Certificate Files (*.pfx;*.p12)|*.pfx;*.p12|All Files (*.*)|*.*"
	$openFileDialog.Title = "Select Client Certificate"
	
	if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
	{
		try
	{
		$password = Get-CertificatePassword
		if (-not $password) { return $false }
		
		# Import the client certificate
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$cert.Import($openFileDialog.FileName, $password,
			"PersistKeySet,Exportable,UserKeySet")
		
		# Store in CurrentUser\My
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
			"MY", "CurrentUser")
		$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$store.Add($cert)
		$store.Close()
		
		return $true
	}
	catch
	{
		[System.Windows.Forms.MessageBox]::Show(
			"Failed to import certificate: $_",
			"Error",
			[System.Windows.Forms.MessageBoxButtons]::OK,
			[System.Windows.Forms.MessageBoxIcon]::Error)
		return $false
	}
	}
	return $false
}

function Set-CertificateValidationPolicy
{
	param (
		[Parameter(Mandatory = $true)]
		[Security.Cryptography.X509Certificates.X509Certificate2]$caCertificate,
		[int]$crlTimeout = 60
	)
	if (-not (Request-AdminRights "certificate policy configuration"))
	{
		throw "Administrator rights are required to configure certificate validation policy"
	}
	
	try
	{
		# Define the registry paths
		$regPaths = @{
			PathValidation = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CertPathValidation"
			ChainEngine    = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
		}
		
		# Create/update CertPathValidation settings
		if (-not (Test-Path $regPaths.PathValidation))
		{
			New-Item -Path $regPaths.PathValidation -Force | Out-Null
			Write-Host "Created new CertPathValidation registry key"
		}
		
		# Configure validation settings
		$pathValidationSettings = @{
			'UseUserTrustedCAs'		     = 1
			'RootCAs'				     = 0
			'URLRetrievalTimeoutSeconds' = $crlTimeout
			'EnableWeakSignatureFlags'   = 0
		}
		
		foreach ($setting in $pathValidationSettings.GetEnumerator())
		{
			$existingValue = Get-ItemProperty -Path $regPaths.PathValidation -Name $setting.Key -ErrorAction SilentlyContinue
			if ($null -ne $existingValue)
			{
				Write-Host "Backing up existing value for $($setting.Key): $existingValue"
				$backupPath = "$($regPaths.PathValidation)\Backup_$($setting.Key)"
				New-ItemProperty -Path $backupPath -Name "OriginalValue" -Value $existingValue -Force | Out-Null
			}
			Set-ItemProperty -Path $regPaths.PathValidation -Name $setting.Key -Value $setting.Value -Force
			Write-Host "Set $($setting.Key) to $($setting.Value)"
		}
		
		# Set explicit trust for the provided CA
		$certPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\$($caCertificate.Thumbprint)"
		if (Test-Path $certPath)
		{
			New-ItemProperty -Path $certPath -Name "Flags" -Value 1 -Type DWORD -Force | Out-Null
			Write-Host "Set explicit trust for certificate: $($caCertificate.Subject)"
		}
		else
		{
			Write-Warning "Certificate path not found for thumbprint: $($caCertificate.Thumbprint)"
		}
		
		# Force policy update
		try
		{
			$process = Start-Process "gpupdate.exe" -ArgumentList "/force" -NoNewWindow -Wait -PassThru
			if ($process.ExitCode -eq 0)
			{
				Write-Host "Group Policy updated successfully"
			}
			else
			{
				Write-Warning "Group Policy update completed with exit code: $($process.ExitCode)"
			}
		}
		catch
		{
			Write-Warning "Could not update Group Policy: $_"
			Write-Host "Changes will apply after next policy refresh"
		}
		
		return $true
	}
	catch
	{
		Write-Error "Failed to set certificate validation policy: $_"
		return $false
	}
}

# Main form setup with improved layout
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Advantive VPN Tool'
$form.Size = New-Object System.Drawing.Size(400, 300) # Increased height and width for better spacing
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

# Define constants for consistent spacing
$margin = 10
$buttonHeight = 25
$buttonWidth = 75
$labelHeight = 20
$controlSpacing = 15 # Consistent spacing between controls

# Top section - Links
$settingsLink = New-Object System.Windows.Forms.LinkLabel
$settingsLink.Location = New-Object System.Drawing.Point($margin, $margin)
$settingsLink.Size = New-Object System.Drawing.Size(50, $labelHeight)
$settingsLink.Text = "Settings"
$settingsLink.LinkColor = [System.Drawing.Color]::Blue
$form.Controls.Add($settingsLink)

$helpLink = New-Object System.Windows.Forms.LinkLabel
$helpLink.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - 50 - $margin), $margin)
$helpLink.Size = New-Object System.Drawing.Size(50, $labelHeight)
$helpLink.Text = "Help"
$helpLink.LinkColor = [System.Drawing.Color]::Blue
$form.Controls.Add($helpLink)

# VPN selection section - moved down for better spacing
$topControlY = $margin + $labelHeight + $controlSpacing
$labelVpn = New-Object System.Windows.Forms.Label
$labelVpn.Location = New-Object System.Drawing.Point($margin, $topControlY)
$labelVpn.Size = New-Object System.Drawing.Size(200, $labelHeight)
$labelVpn.Text = 'Select VPN connection:'
$form.Controls.Add($labelVpn)

$comboBoxVpn = New-Object System.Windows.Forms.ComboBox
$comboBoxVpn.Location = New-Object System.Drawing.Point($margin, ($labelVpn.Bottom + 5))
$comboBoxVpn.Size = New-Object System.Drawing.Size(($form.ClientSize.Width - $margin * 2), $labelHeight)
$comboBoxVpn.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$form.Controls.Add($comboBoxVpn)

# Tunnel mode section - ensure proper vertical spacing
$labelRoute = New-Object System.Windows.Forms.Label
$labelRoute.Location = New-Object System.Drawing.Point($margin, ($comboBoxVpn.Bottom + $controlSpacing))
$labelRoute.Size = New-Object System.Drawing.Size(170, $labelHeight)
$labelRoute.Text = 'Tunnel Mode (stop VPN to change):'
$form.Controls.Add($labelRoute)

# Create panel for checkboxes to keep them aligned
$tunnelPanel = New-Object System.Windows.Forms.Panel
$tunnelPanel.Location = New-Object System.Drawing.Point($margin, ($labelRoute.Bottom + 5))
$tunnelPanel.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($tunnelPanel)

$checkBoxFull = New-Object System.Windows.Forms.CheckBox
$checkBoxFull.Location = New-Object System.Drawing.Point(0, 0)
$checkBoxFull.Size = New-Object System.Drawing.Size(90, $labelHeight)
$checkBoxFull.Text = 'Full Tunnel'
$tunnelPanel.Controls.Add($checkBoxFull)

$checkBoxSplit = New-Object System.Windows.Forms.CheckBox
$checkBoxSplit.Location = New-Object System.Drawing.Point(100, 0)
$checkBoxSplit.Size = New-Object System.Drawing.Size(90, $labelHeight)
$checkBoxSplit.Text = 'Split Tunnel'
$tunnelPanel.Controls.Add($checkBoxSplit)

# Right-side buttons - align properly
$rightButtonX = $form.ClientSize.Width - $buttonWidth - $margin
$buttonApply = New-Object System.Windows.Forms.Button
$buttonApply.Location = New-Object System.Drawing.Point($rightButtonX, $labelRoute.Top)
$buttonApply.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonApply.Text = 'Apply'
$form.Controls.Add($buttonApply)

$buttonConnect = New-Object System.Windows.Forms.Button
$buttonConnect.Location = New-Object System.Drawing.Point($rightButtonX, ($buttonApply.Bottom + 5))
$buttonConnect.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonConnect.Text = 'Connect'
$form.Controls.Add($buttonConnect)

$buttonRestartIPSec = New-Object System.Windows.Forms.Button
$buttonRestartIPSec.Location = New-Object System.Drawing.Point($rightButtonX, ($buttonConnect.Bottom + 5))
$buttonRestartIPSec.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonRestartIPSec.Text = 'Restart/Srv'
$form.Controls.Add($buttonRestartIPSec)

# Installation buttons panel - ensure it's positioned below the tunnel panel with adequate spacing
$installPanel = New-Object System.Windows.Forms.Panel
$installPanel.Location = New-Object System.Drawing.Point($margin, ($tunnelPanel.Bottom + $controlSpacing))
$panelWidth = $form.ClientSize.Width - ($margin * 2)
$panelHeight = $buttonHeight + 5
$installPanel.Size = New-Object System.Drawing.Size($panelWidth, $panelHeight)
$form.Controls.Add($installPanel)

# Calculate proper button spacing within the panel
$buttonSpacing = 10
$totalButtonWidth = ($buttonWidth * 3) + ($buttonSpacing * 2)
# Calculate the starting X position to center the buttons
$firstButtonX = ($installPanel.Width - $totalButtonWidth) / 2

# Position installation buttons with even spacing
$buttonRemove = New-Object System.Windows.Forms.Button
$buttonRemove.Location = New-Object System.Drawing.Point($firstButtonX, 0)
$buttonRemove.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonRemove.Text = 'Uninstall'
$installPanel.Controls.Add($buttonRemove)

$buttonInstall = New-Object System.Windows.Forms.Button
$buttonInstall.Location = New-Object System.Drawing.Point(($buttonRemove.Right + $buttonSpacing), 0)
$buttonInstall.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonInstall.Text = 'Install/Okta'
$installPanel.Controls.Add($buttonInstall)

$buttonTlsInstall = New-Object System.Windows.Forms.Button
$buttonTlsInstall.Location = New-Object System.Drawing.Point(($buttonInstall.Right + $buttonSpacing), 0)
$buttonTlsInstall.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$buttonTlsInstall.Text = 'Install/TLS'
$installPanel.Controls.Add($buttonTlsInstall)

# Status label to show program state - ensure it's at the bottom with proper spacing
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point($margin, ($form.ClientSize.Height - $labelHeight - $margin))
$statusLabel.Size = New-Object System.Drawing.Size(($form.ClientSize.Width - $margin * 2), $labelHeight)
$statusLabel.Text = "Ready"
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$statusLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($statusLabel)

# Fix positioning - move the install panel lower if needed
$installPanel.Location = New-Object System.Drawing.Point($margin, ($tunnelPanel.Bottom + 25))

# Ensure proper button spacing in the install panel
$buttonWidth = 75
$buttonSpacing = 10
$firstButtonX = ($installPanel.Width - (3 * $buttonWidth) - (2 * $buttonSpacing)) / 2

# Reposition buttons with even spacing
$buttonRemove.Location = New-Object System.Windows.Forms.Point($firstButtonX, 0)
$buttonInstall.Location = New-Object System.Windows.Forms.Point(($buttonRemove.Right + $buttonSpacing), 0)
$buttonTlsInstall.Location = New-Object System.Windows.Forms.Point(($buttonInstall.Right + $buttonSpacing), 0)

# Event handler for VPN selection
$comboBoxVpn.Add_SelectedIndexChanged({
	$selectedVpn = $comboBoxVpn.SelectedItem
	if ($selectedVpn -and $selectedVpn -ne "<No VPNs Found>") {
		try {
			$vpn = Get-VpnConnection -Name $selectedVpn -ErrorAction Stop
				$statusLabel.Text = if ($vpn.ConnectionStatus -eq "Connected") { "Connected: $selectedVpn" }
				else { "Selected: $selectedVpn" }
			}
			catch
			{
				if ($_.Exception.Message -match "Access is denied")
				{
					$statusLabel.Text = "Permission error: Unable to retrieve VPN details for $selectedVpn"
				}
				elseif ($_.Exception.Message -match "Cannot find VPN connection")
				{
					$statusLabel.Text = "Invalid VPN: $selectedVpn does not exist"
				}
				else
				{
					$statusLabel.Text = "Error retrieving VPN: $selectedVpn"
				}
			}
		}
		else
		{
			$statusLabel.Text = "No VPN selected"
		}
		$form.Refresh()
	})

$buttonConnect.Add_Click({
		Start-Process "rasphone"
		$statusLabel.Text = "Opening Rasphone..."
		$form.Refresh()
		Start-Sleep -Milliseconds 500
		$form.Hide()
		$form.ShowInTaskbar = $false
	})

$buttonRestartIPSec.Add_Click({
	try
	{
		if (-not (Test-IsAdmin))
		{
			$statusLabel.Text = "IPSec restart requires admin privileges"
			$form.Refresh()
			
			# Try to elevate using the Request-AdminRights function
			if (-not (Request-AdminRights "IPSec service restart"))
			{
				$statusLabel.Text = "Admin rights request was denied"
				$form.Refresh()
				Start-Sleep -Seconds 2
				$statusLabel.Text = "Ready"
				return
			}
			# If we get here, the elevated process has completed
			$statusLabel.Text = "IPSec services restarted via elevated process"
			$form.Refresh()
			Start-Sleep -Seconds 1
			$statusLabel.Text = "Ready"
			return
		}
			
		$statusLabel.Text = "Restarting IPSec services..."
		$form.Refresh()

		# Define all IPsec-related services
		$services = @("IKEEXT", "PolicyAgent", "BFE", "MpsSvc")
		$serviceStopErrors = @()
		$serviceStartErrors = @()

		# Stop services in reverse dependency order (MpsSvc -> BFE -> PolicyAgent -> IKEEXT)
		$statusLabel.Text = "Stopping IPSec services..."
		$form.Refresh()
		foreach ($svc in $services | Sort-Object -Descending) {
			try {
				$service = Get-Service -Name $svc -ErrorAction Stop
				if ($service.Status -eq "Running") {
					Stop-Service -Name $svc -Force -ErrorAction Stop
					Write-Host "Stopped service: $svc"
				}
			}
			catch [System.InvalidOperationException] {
				$msg = "Service $svc not found or cannot be accessed"
				$serviceStopErrors += $msg
				Write-Host $msg
			}
			catch [System.ComponentModel.Win32Exception] {
				$msg = "Access denied when stopping $svc"
				$serviceStopErrors += $msg
				Write-Host $msg
			}
			catch {
				$msg = "Error stopping ${svc}: $($_.Exception.Message)"
				$serviceStopErrors += $msg
				Write-Host $msg
			}
		}

		# Wait to ensure services are fully stopped
		Start-Sleep -Seconds 3

		# Start services in dependency order (BFE -> MpsSvc -> PolicyAgent -> IKEEXT)
		$statusLabel.Text = "Starting IPSec services..."
		$form.Refresh()
		foreach ($svc in $services) {
			try {
				Start-Service -Name $svc -ErrorAction Stop
				Write-Host "Started service: $svc"
			}
			catch [System.InvalidOperationException] {
				$msg = "Service $svc not found or cannot be accessed"
				$serviceStartErrors += $msg
				Write-Host $msg
			}
			catch [System.ComponentModel.Win32Exception] {
				$msg = "Access denied when starting $svc"
				$serviceStartErrors += $msg
				Write-Host $msg
			}
			catch {
				$msg = "Error starting ${svc}: $($_.Exception.Message)"
				$serviceStartErrors += $msg
				Write-Host $msg
			}
		}

		# Verify all services are running
		$statusLabel.Text = "Verifying IPSec services..."
		$form.Refresh()
		Start-Sleep -Seconds 2
		$serviceVerifyErrors = @()
		foreach ($svc in $services) {
			try {
				$service = Get-Service -Name $svc -ErrorAction Stop
				if ($service.Status -ne "Running") {
					$msg = "Service $svc is not running"
					$serviceVerifyErrors += $msg
					Write-Host $msg
				}
			}
			catch {
				$msg = "Cannot verify $svc status: $($_.Exception.Message)"
				$serviceVerifyErrors += $msg
				Write-Host $msg
			}
		}

		# Display appropriate status message
		if ($serviceStopErrors.Count -gt 0 -or $serviceStartErrors.Count -gt 0 -or $serviceVerifyErrors.Count -gt 0) {
			$errorCount = $serviceStopErrors.Count + $serviceStartErrors.Count + $serviceVerifyErrors.Count
			$statusLabel.Text = "IPSec restart completed with $errorCount issues"
			$form.Refresh()
			
			# Log all errors for troubleshooting
			Write-Host "Stop errors: $($serviceStopErrors -join ', ')"
			Write-Host "Start errors: $($serviceStartErrors -join ', ')"
			Write-Host "Verify errors: $($serviceVerifyErrors -join ', ')"
		}
		else {
			$statusLabel.Text = "IPSec services restarted successfully"
			$form.Refresh()
		}
		Start-Sleep -Seconds 1
		$statusLabel.Text = "Ready"
	}
	catch
	{
		$statusLabel.Text = "Error restarting IPSec: $_"
		$form.Refresh()
		Write-Host "Error restarting IPSec services: $($_.Exception.Message)"
		Start-Sleep -Seconds 2
		$statusLabel.Text = "Ready"
	}
	finally
	{
		# Ensure the form updates even if an error occurs
		$form.Refresh()
	}
})
            

$buttonApply.Add_Click({
		$selectedVpn = $comboBoxVpn.SelectedItem
		if (-not $selectedVpn -or $selectedVpn -eq "<No VPNs Found>")
		{
			$statusLabel.Text = "Please select a VPN profile"
			$form.Refresh()
			Start-Sleep -Seconds 1
			$statusLabel.Text = "Ready"
			return
		}
		try
		{
			Get-VpnConnection -Name $selectedVpn -ErrorAction Stop | Out-Null
		}
		catch
		{
			$statusLabel.Text = "Selected VPN profile does not exist"
			$form.Refresh()
			Start-Sleep -Seconds 1
			$statusLabel.Text = "Ready"
			return
		}
		if ($checkBoxFull.Checked -eq $checkBoxSplit.Checked)
		{
			$statusLabel.Text = "Select Full or Split Tunnel, not both"
			$form.Refresh()
			Start-Sleep -Seconds 1
			$statusLabel.Text = "Ready"
			return
		}
		try
		{
			$statusLabel.Text = "Applying tunnel configuration..."
			$form.Refresh()
			if ($checkBoxFull.Checked)
			{
				Set-VpnConnection -Name $selectedVpn -SplitTunneling $false
				$statusLabel.Text = "Full Tunnel applied to $selectedVpn"
			}
			else
			{
				Set-VpnConnection -Name $selectedVpn -SplitTunneling $true
				$statusLabel.Text = "Split Tunnel applied to $selectedVpn"
			}
			$form.Refresh()
			Start-Sleep -Seconds 1
			Update-VpnStatus
		}
		catch
		{
			$statusLabel.Text = "Error applying config: $_"
			$form.Refresh()
			Start-Sleep -Seconds 2
			$statusLabel.Text = "Ready"
		}
	})

$helpLink.Add_Click({
		try
		{
			Start-Process "https://advantiveadmin.sharepoint.com/:b:/r/sites/Development/Shared%20Documents/02-Output/01-Development/06-Kiwiplan/111-%20Devops/kpaws-access%20(1).pdf?csf=1&web=1&e=3FxMbd"
			$statusLabel.Text = "Opening help document..."
			$form.Refresh()
			Start-Sleep -Milliseconds 500
			$statusLabel.Text = "Ready"
		}
		catch
		{
			$statusLabel.Text = "Error opening help: $_"
			$form.Refresh()
			Start-Sleep -Seconds 2
			$statusLabel.Text = "Ready"
		}
	})

$settingsLink.Add_Click({
    $keys = @("vpnName", "serverAddress", "destinationPrefixes", "caUrl", "crlUrl")
    $controls = @{ }
    $y = 10
    
    $settingsForm = New-Object System.Windows.Forms.Form
    $settingsForm.Text = 'Settings'
    $settingsForm.Size = New-Object System.Drawing.Size(345, 395)
    $settingsForm.StartPosition = 'Manual'
    $settingsForm.FormBorderStyle = 'FixedDialog'
    $settingsForm.MaximizeBox = $false
    
    $mainFormRightEdge = $form.Location.X + $form.Width
    $settingsForm.Location = New-Object System.Drawing.Point($mainFormRightEdge, $form.Location.Y)
    
    foreach ($key in $keys)
    {
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, $y)
        $label.Size = New-Object System.Drawing.Size(120, 20)
        $label.Text = $key
        $settingsForm.Controls.Add($label)
        
        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(140, $y)
        $textBox.Size = New-Object System.Drawing.Size(180, 20)
        if ([System.Configuration.ConfigurationManager]::AppSettings.AllKeys -contains $key)
        {
            $value = [System.Configuration.ConfigurationManager]::AppSettings[$key]
            if ($value) { $textBox.Text = $value }
        }
        $settingsForm.Controls.Add($textBox)
        $controls[$key] = $textBox
        $y += 30
    }
    
    $labelDnsSuffixes = New-Object System.Windows.Forms.Label
    $labelDnsSuffixes.Location = New-Object System.Drawing.Point(10, $y)
    $labelDnsSuffixes.Size = New-Object System.Drawing.Size(120, 20)
    $labelDnsSuffixes.Text = "DNS Suffixes"
    $settingsForm.Controls.Add($labelDnsSuffixes)
    
    $textBoxDnsSuffixes = New-Object System.Windows.Forms.TextBox
    $textBoxDnsSuffixes.Location = New-Object System.Drawing.Point(140, $y)
    $textBoxDnsSuffixes.Size = New-Object System.Drawing.Size(180, 20)
    $dnsSuffixesValue = [System.Configuration.ConfigurationManager]::AppSettings["dnsSuffixes"]
    if ($dnsSuffixesValue) { $textBoxDnsSuffixes.Text = $dnsSuffixesValue }
    $settingsForm.Controls.Add($textBoxDnsSuffixes)
    $controls["dnsSuffixes"] = $textBoxDnsSuffixes
    $y += 30
    
    $checkBoxPullCA = New-Object System.Windows.Forms.CheckBox
    $checkBoxPullCA.Location = New-Object System.Drawing.Point(10, $y)
    $checkBoxPullCA.Size = New-Object System.Drawing.Size(150, 20)
    $checkBoxPullCA.Text = "Pull CA on Install"
    $pullCAValue = [System.Configuration.ConfigurationManager]::AppSettings["pullCA"]
    $checkBoxPullCA.Checked = if ($pullCAValue -eq "true") { $true }
    else { $false }
    $settingsForm.Controls.Add($checkBoxPullCA)
    $y += 30
    
    $checkBoxPullCRL = New-Object System.Windows.Forms.CheckBox
    $checkBoxPullCRL.Location = New-Object System.Drawing.Point(10, $y)
    $checkBoxPullCRL.Size = New-Object System.Drawing.Size(150, 20)
    $checkBoxPullCRL.Text = "Pull CRL on Install"
    $pullCRLValue = [System.Configuration.ConfigurationManager]::AppSettings["pullCRL"]
    $checkBoxPullCRL.Checked = if ($pullCRLValue -eq "true") { $true }
    else { $false }
    $settingsForm.Controls.Add($checkBoxPullCRL)
    $y += 30
    
    $checkBoxUseDnsSuffix = New-Object System.Windows.Forms.CheckBox
    $checkBoxUseDnsSuffix.Location = New-Object System.Drawing.Point(10, $y)
    $checkBoxUseDnsSuffix.Size = New-Object System.Drawing.Size(250, 30)
    $checkBoxUseDnsSuffix.Text = "Use this connection's DNS suffix in DNS registration"
    $useDnsSuffixValue = [System.Configuration.ConfigurationManager]::AppSettings["useDnsSuffixInDnsRegistration"]
    $checkBoxUseDnsSuffix.Checked = if ($useDnsSuffixValue -eq "true") { $true }
    else { $false }
    $settingsForm.Controls.Add($checkBoxUseDnsSuffix)
    $y += 30
    
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Location = New-Object System.Drawing.Point(10, $y)
    $btnSave.Size = New-Object System.Drawing.Size(150, 30)
    $btnSave.Text = "Save Settings"
    $btnSave.Add_Click({
        try
        {
            $exePath = [System.Reflection.Assembly]::GetExecutingAssembly().Location
            $config = [System.Configuration.ConfigurationManager]::OpenExeConfiguration($exePath)
            foreach ($key in $keys)
            {
                if ($config.AppSettings.Settings[$key])
                {
                    $config.AppSettings.Settings[$key].Value = $controls[$key].Text
                }
                else
                {
                    $config.AppSettings.Settings.Add($key, $controls[$key].Text)
                }
            }
            if ($config.AppSettings.Settings["dnsSuffixes"])
            {
                $config.AppSettings.Settings["dnsSuffixes"].Value = $textBoxDnsSuffixes.Text
            }
            else
            {
                $config.AppSettings.Settings.Add("dnsSuffixes", $textBoxDnsSuffixes.Text)
            }
            if ($config.AppSettings.Settings["pullCA"])
            {
                $config.AppSettings.Settings["pullCA"].Value = $checkBoxPullCA.Checked.ToString().ToLower()
            }
            else
            {
                $config.AppSettings.Settings.Add("pullCA", $checkBoxPullCA.Checked.ToString().ToLower())
            }
            if ($config.AppSettings.Settings["pullCRL"])
            {
                $config.AppSettings.Settings["pullCRL"].Value = $checkBoxPullCRL.Checked.ToString().ToLower()
            }
            else
            {
                $config.AppSettings.Settings.Add("pullCRL", $checkBoxPullCRL.Checked.ToString().ToLower())
            }
            if ($config.AppSettings.Settings["useDnsSuffixInDnsRegistration"])
            {
                $config.AppSettings.Settings["useDnsSuffixInDnsRegistration"].Value = $checkBoxUseDnsSuffix.Checked.ToString().ToLower()
            }
            else
            {
                $config.AppSettings.Settings.Add("useDnsSuffixInDnsRegistration", $checkBoxUseDnsSuffix.Checked.ToString().ToLower())
            }
            $config.Save([System.Configuration.ConfigurationSaveMode]::Modified)
            [System.Configuration.ConfigurationManager]::RefreshSection("appSettings")
            $statusLabel.Text = "Settings saved"
            $form.Refresh()
            Start-Sleep -Seconds 1
            $statusLabel.Text = "Ready"
        }
        catch
        {
            $statusLabel.Text = "Error saving settings: $_"
            $form.Refresh()
            Start-Sleep -Seconds 2
            $statusLabel.Text = "Ready"
        }
    })
    $settingsForm.Controls.Add($btnSave)
    
    $btnRemoveCA = New-Object System.Windows.Forms.Button
    $btnRemoveCA.Location = New-Object System.Drawing.Point(170, $y)
    $btnRemoveCA.Size = New-Object System.Drawing.Size(150, 30)
    $btnRemoveCA.Text = "Remove Installed CA"
    $btnRemoveCA.Add_Click({
        $caUrlValue = $controls["caUrl"].Text
        if (-not $caUrlValue)
        {
            $statusLabel.Text = "CA URL is empty"
            $form.Refresh()
            Start-Sleep -Seconds 1
            $statusLabel.Text = "Ready"
            return
        }
        Remove-InstalledCA -caUrl $caUrlValue
    })
    $settingsForm.Controls.Add($btnRemoveCA)
    
    $y += 40
    
    $btnPullCACRL = New-Object System.Windows.Forms.Button
    $btnPullCACRL.Location = New-Object System.Drawing.Point(10, $y)
    $btnPullCACRL.Size = New-Object System.Drawing.Size(310, 30)
    $btnPullCACRL.Text = 'Pull CA/CRL Certificates'
    $btnPullCACRL.Add_Click({
        $caUrl = $controls["caUrl"].Text
        $crlUrl = $controls["crlUrl"].Text
        
        if ([string]::IsNullOrEmpty($caUrl) -and [string]::IsNullOrEmpty($crlUrl))
        {
            $statusLabel.Text = "Both CA URL and CRL URL are empty"
            $form.Refresh()
            Start-Sleep -Seconds 2
            $statusLabel.Text = "Ready"
            return
        }
        
        $result = Update-CACertificates -caUrl $caUrl -crlUrl $crlUrl
        if (-not $result)
        {
            $statusLabel.Text = "Failed to update CA/CRL certificates"
            $form.Refresh()
            Start-Sleep -Seconds 2
            $statusLabel.Text = "Ready"
            return
        }
        
        $result = Update-CACertificates -caUrl $caUrl -crlUrl $crlUrl
        
        if ($result)
        {
            $statusLabel.Text = "Ready"
        }
    })
    $settingsForm.Controls.Add($btnPullCACRL)
    
    function Remove-InstalledCA
    {
        param ([string]$caUrl)
        
        if (-not (Request-AdminRights "CA certificate removal"))
        {
            $statusLabel.Text = "CA removal requires admin rights"
            $form.Refresh()
            Start-Sleep -Seconds 2
            $statusLabel.Text = "Ready"
            return $false
        }
        
        $tempFile = [System.IO.Path]::GetTempFileName()
        try
        {
            $statusLabel.Text = "Removing CA certificate..."
            $form.Refresh()
            
            Invoke-WebRequest -Uri $caUrl -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
            $certPem = Get-Content $tempFile -Raw
            $base64 = $certPem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
            while ($base64.Length % 4 -ne 0) { $base64 += '=' }
            $certBytes = [System.Convert]::FromBase64String($base64)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($certBytes)
            
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("ROOT", "LocalMachine")
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            $found = $false
            foreach ($c in $store.Certificates)
            {
                if ($c.Thumbprint -eq $cert.Thumbprint)
                {
                    $store.Remove($c)
                    $statusLabel.Text = "Removed cert: $($cert.Thumbprint)"
                    $found = $true
                }
            }
            
            if (-not $found)
            {
                $statusLabel.Text = "Certificate not found in store"
            }
            
            $store.Close()
            $form.Refresh()
            Start-Sleep -Seconds 1
            $statusLabel.Text = "Ready"
            return $true
        }
        catch
        {
            $statusLabel.Text = "Error removing CA: $_"
            $form.Refresh()
            Start-Sleep -Seconds 2
            $statusLabel.Text = "Ready"
            return $false
        }
        finally
        {
            if ($cert) { $cert.Dispose() }
            if ($store) { $store.Dispose() }
            if (Test-Path $tempFile)
            {
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    $settingsForm.ShowDialog() | Out-Null
})

$buttonRemove.Add_Click({
		$selectedVpn = $comboBoxVpn.SelectedItem
		if (-not $selectedVpn -or $selectedVpn -eq "<No VPNs Found>")
		{
			$statusLabel.Text = "Please select a VPN to remove"
			$form.Refresh()
			Start-Sleep -Seconds 1
			$statusLabel.Text = "Ready"
			return
		}
		try
		{
			$statusLabel.Text = "Removing VPN: $selectedVpn..."
			$form.Refresh()
			Remove-VpnConnection -Name $selectedVpn -Force -ErrorAction SilentlyContinue
			Update-VpnList
			$statusLabel.Text = "VPN '$selectedVpn' removed"
			$form.Refresh()
			Start-Sleep -Seconds 1
			Update-VpnStatus
		}
		catch
		{
			$statusLabel.Text = "Error removing VPN: $_"
			$form.Refresh()
			Start-Sleep -Seconds 2
			$statusLabel.Text = "Ready"
		}
	})

function Update-VpnStatus
{
	$vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
	if ($vpnConnections)
	{
		$connectedVpn = $vpnConnections | Where-Object { $_.ConnectionStatus -eq "Connected" } | Select-Object -First 1 -ExpandProperty Name
	if ($connectedVpn)
	{
		$statusText = "Connected: $connectedVpn"
	}
	else
	{
		$statusText = "Disconnected"
	}
}
else
{
	$statusText = "No VPN connections found"
}
# Buttons are already defined and added to installPanel - do not add them directly to the form
$trayIcon.Text = "Advantive VPN Tool`n$statusText"
	$statusLabel.Text = $statusText
	$form.Refresh()
}

function Update-VpnList
{
	$comboBoxVpn.Items.Clear()
	try
	{
		$vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
		if ($vpnConnections)
		{
			foreach ($vpn in $vpnConnections)
			{
				$comboBoxVpn.Items.Add($vpn.Name)
			}
			# Auto-select the first VPN if available
			if ($comboBoxVpn.Items.Count -gt 0)
			{
				$comboBoxVpn.SelectedIndex = 0
			}
		}
		else
		{
			$comboBoxVpn.Items.Add("<No VPNs Found>")
			$comboBoxVpn.SelectedIndex = 0
		}
	}
	catch
	{
		$statusLabel.Text = "Error retrieving VPNs: $_"
		$form.Refresh()
		Start-Sleep -Seconds 2
		$statusLabel.Text = "Ready"
	}
	$comboBoxVpn.Refresh()
	Update-VpnStatus
}
$form.Add_Load({ Update-VpnList })

# EAP XML configuration
$eapXmlContent = @"
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
  <EapMethod>
    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
    <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
    <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
  </EapMethod>
  <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
    <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
      <ServerValidation>
        <ServerNames></ServerNames>
        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
      </ServerValidation>
      <Phase2Authentication>
        <PAPAuthentication />
      </Phase2Authentication>
      <Phase1Identity>
        <IdentityPrivacy>false</IdentityPrivacy>
      </Phase1Identity>
    </EapTtls>
  </Config>
</EapHostConfig>
"@
$eapXml = [xml]$eapXmlContent

$buttonInstall.Add_Click({
		try
		{
			Add-Type -AssemblyName System.Configuration
			
			$statusLabel.Text = "Loading configuration..."
			$form.Refresh()
			
			$vpnName = [System.Configuration.ConfigurationManager]::AppSettings["vpnName"]
			$serverAddress = [System.Configuration.ConfigurationManager]::AppSettings["serverAddress"]
			$destinationPrefixesRaw = [System.Configuration.ConfigurationManager]::AppSettings["destinationPrefixes"]
			$caUrl = [System.Configuration.ConfigurationManager]::AppSettings["caUrl"]
			$crlUrl = [System.Configuration.ConfigurationManager]::AppSettings["crlUrl"]
			$pullCA = [System.Configuration.ConfigurationManager]::AppSettings["pullCA"] -eq "true"
			$pullCRL = [System.Configuration.ConfigurationManager]::AppSettings["pullCRL"] -eq "true"
			$useDnsSuffixInDnsRegistration = [System.Configuration.ConfigurationManager]::AppSettings["useDnsSuffixInDnsRegistration"] -eq "true"
			if ($useDnsSuffixInDnsRegistration)
			{
				Set-VpnConnection -Name $vpnName -DnsSuffixInDnsRegistration $true -ErrorAction SilentlyContinue
			}
			
			# Validate critical configuration values
			if (-not $vpnName) { throw "VPN name is not configured in settings." }
			if (-not $serverAddress) { throw "Server address is not configured in settings." }
			if (-not $destinationPrefixesRaw) { throw "Destination prefixes are not configured in settings." }
			
			$destinationPrefixes = $destinationPrefixesRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
			if (-not $destinationPrefixes) { throw "No valid destination prefixes found in settings." }
			
			$dnsSuffixesRaw = [System.Configuration.ConfigurationManager]::AppSettings["dnsSuffixes"]
			$dnsSuffixes = if ([string]::IsNullOrWhiteSpace($dnsSuffixesRaw))
			{
				@()
			}
			else
			{
				$dnsSuffixesRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
			}
			
			$statusLabel.Text = "Validating DNS suffixes..."
			$form.Refresh()
			if ($dnsSuffixes.Count -gt 0)
			{
				$invalidSuffixes = $dnsSuffixes | Where-Object { $_ -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$' }
				if ($invalidSuffixes)
				{
					$statusLabel.Text = "Invalid DNS suffix: " + ($invalidSuffixes -join ', ')
					$form.Refresh()
					Start-Sleep -Seconds 2
					$statusLabel.Text = "Ready"
					return
				}
			}
			
			# Dynamically determine certificate store based on admin status
			$isAdmin = Test-IsAdmin
			$storeLocation = if ($isAdmin) { "LocalMachine" }
			else { "CurrentUser" }
			$certStore = "Cert:\$storeLocation\Root"
			$caDest = if ($pullCA) { [System.IO.Path]::GetTempFileName() }
			else { $null }
			$crlDest = if ($pullCRL) { [System.IO.Path]::GetTempFileName() }
			else { $null }
			
			function Test-CertificateExists
			{
				param ([string]$thumbprint)
				$cert = Get-ChildItem -Path $certStore | Where-Object { $_.Thumbprint -eq $thumbprint }
				return $null -ne $cert
			}
			
			if ($pullCA)
			{
				try
				{
					if (-not $caUrl) { throw "CA URL is not configured in settings." }
					if (-not (Request-AdminRights "CA certificate installation"))
					{
						throw "Administrator rights are required to install the CA certificate"
					}
					$statusLabel.Text = "Downloading CA certificate..."
					$form.Refresh()
					Invoke-WebRequest -Uri $caUrl -OutFile $caDest -UseBasicParsing -ErrorAction Stop
					if ((Get-Content $caDest -Raw).Length -eq 0)
					{
						throw "The downloaded CA file is empty. Check the URL or server response."
					}
					
					if ($pullCA)
					{
						if (-not (Request-AdminRights "CA certificate installation"))
						{
							throw "Administrator rights required to install the CA certificate"
						}
						
						$statusLabel.Text = "Installing CA certificate..."
						$form.Refresh()
						
						# Install CA cert (this will handle elevation)
						$cert = Get-CACertificate -Url $caUrl
						Install-CACertificate -cert $cert
					}
					$form.Refresh()
					Start-Sleep -Seconds 1
					if (Test-IsAdmin)
					{
						Write-Host "Setting certificate validation policy..."
						if (Set-CertificateValidationPolicy -caCertificate $cert)
						{
							Write-Host "Certificate validation policy set successfully."
						}
						else
						{
							Write-Warning "Failed to set certificate validation policy"
						}
					}
					else
					{
						Write-Host "Admin privileges required to set certificate validation policy."
					}
				}
				finally
				{
					if ($cert) { $cert.Dispose() }
					if ($store) { $store.Dispose() }
				}
			}
			
			if ($pullCRL)
			{
				try
				{
					if (-not $crlUrl) { throw "CRL URL is not configured in settings." }
					if (-not (Request-AdminRights "CA certificate installation"))
					{
						throw "Administrator rights are required to install the CA certificate"
					}
					$statusLabel.Text = "Downloading CRL..."
					$form.Refresh()
					Invoke-WebRequest -Uri $crlUrl -OutFile $crlDest -UseBasicParsing -ErrorAction Stop
					if ((Get-Content $crlDest -Raw).Length -eq 0)
					{
						throw "The downloaded CRL file is empty. Check the URL or server response."
					}
					
					try
					{
						$crlBytes = [System.IO.File]::ReadAllBytes($crlDest)
						$derPath = [System.IO.Path]::GetTempFileName()
						[System.IO.File]::WriteAllBytes($derPath, $crlBytes)
						& certutil -urlfetch -f $crlUrl | Out-Null
						$statusLabel.Text = "CRL fetched and cached"
						$form.Refresh()
						Start-Sleep -Seconds 1
						Remove-Item -Path $derPath -Force -ErrorAction SilentlyContinue
					}
					catch
					{
						$statusLabel.Text = "Failed to process CRL: " + $_.Exception.Message
						$form.Refresh()
						Start-Sleep -Seconds 2
						$statusLabel.Text = "Ready"
						return
					}
				}
				finally
				{
					if ($pullCA -and $caDest -and (Test-Path $caDest))
					{
						Remove-Item -Path $caDest -Force -ErrorAction SilentlyContinue
					}
					if ($pullCRL -and $crlDest -and (Test-Path $crlDest))
					{
						Remove-Item -Path $crlDest -Force -ErrorAction SilentlyContinue
					}
				}
			}
			
			# Rest of VPN installation code...
			$existingVpn = Get-VpnConnection -Name $vpnName -ErrorAction SilentlyContinue
			if ($existingVpn)
			{
				$statusLabel.Text = "Removing existing VPN..."
				$form.Refresh()
				try
				{
					Remove-VpnConnection -Name $vpnName -Force -ErrorAction Stop
					Start-Sleep -Seconds 1
				}
				catch
				{
					$statusLabel.Text = "Failed to remove existing VPN: $_"
					$form.Refresh()
					Start-Sleep -Seconds 2
					return
				}
			}
			
			$statusLabel.Text = "Installing VPN..."
			$form.Refresh()
			Add-VpnConnection -Name $vpnName `
							  -ServerAddress $serverAddress `
							  -TunnelType IKEv2 `
							  -EncryptionLevel Maximum `
							  -AuthenticationMethod Eap `
							  -EapConfigXmlStream $eapXml.OuterXml `
							  -RememberCredential $False `
							  -Force
			
			# Add delay to ensure VPN is fully registered
			Start-Sleep -Seconds 3
			
			if ($dnsSuffixes.Count -gt 0)
			{
				$statusLabel.Text = "Adding DNS suffixes: " + ($dnsSuffixes -join ', ')
				$form.Refresh()
				Start-Sleep -Milliseconds 500
				foreach ($dnsSuffix in $dnsSuffixes)
				{
					try
					{
						$statusLabel.Text = "Adding DNS suffix: $dnsSuffix"
						$form.Refresh()
						Add-VpnConnectionTriggerDnsConfiguration -ConnectionName $vpnName `
																 -DnsSuffix $dnsSuffix `
																 -Force `
																 -ErrorAction Stop
						$statusLabel.Text = "Added DNS suffix: $dnsSuffix"
						$form.Refresh()
						Start-Sleep -Milliseconds 500
					}
					catch
					{
						$statusLabel.Text = "Error adding DNS suffix " + $dnsSuffix + ": " + $_.Exception.Message
						$form.Refresh()
						Start-Sleep -Seconds 1
					}
				}
			}
			else
			{
				$statusLabel.Text = "No DNS suffixes to add"
				$form.Refresh()
				Start-Sleep -Seconds 1
			}
			
			$statusLabel.Text = "Setting IPsec configuration..."
			$form.Refresh()
			Set-VpnConnectionIPsecConfiguration -ConnectionName "$vpnName" `
												-AuthenticationTransformConstants SHA256 `
												-CipherTransformConstants GCMAES256 `
												-EncryptionMethod AES256 `
												-IntegrityCheckMethod SHA256 `
												-DHGroup ECP256 `
												-PfsGroup ECP256 `
												-PassThru `
												-Force
			
			$statusLabel.Text = "Adding VPN routes..."
			$form.Refresh()
			foreach ($prefix in $destinationPrefixes)
			{
				Add-VpnConnectionRoute -ConnectionName $vpnName -DestinationPrefix $prefix -PassThru -ErrorAction SilentlyContinue
			}
			
			Update-VpnList
			$statusLabel.Text = "VPN installed successfully"
			$form.Refresh()
			Start-Sleep -Seconds 1
			Update-VpnStatus
		}
		catch
		{
			$statusLabel.Text = "Installation failed: " + $_.Exception.Message
			$form.Refresh()
			Start-Sleep -Seconds 2
			$statusLabel.Text = "Ready"
		}
		finally
		{
			Update-VpnStatus
		}
	})

$eaptlsXmlContent = @"
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
  <EapMethod>
    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
  </EapMethod>
  <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
    <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
      <Type>13</Type>
      <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
        <CredentialsSource>
          <CertificateStore>
            <SimpleCertSelection>true</SimpleCertSelection>
          </CertificateStore>
        </CredentialsSource>
        <ServerValidation>
          <ServerNames></ServerNames>
          <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
        </ServerValidation>
        <DifferentUsername>false</DifferentUsername>
        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
        <TLSExtensions xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">
          <FilteringInfo xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3">
            <ClientAuthEKUList Enabled="true">
              <EKUMapInList>Client Authentication</EKUMapInList>
            </ClientAuthEKUList>
          </FilteringInfo>
        </TLSExtensions>
      </EapType>
    </Eap>
  </Config>
</EapHostConfig>
"@

function Test-UserCertificateAvailable
{
	$userStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("MY", "CurrentUser")
	try
	{
		$userStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
		$clientCerts = $userStore.Certificates.Find(
			[System.Security.Cryptography.X509Certificates.X509FindType]::FindByTimeValid,
			[System.DateTime]::Now,
			$true
		).Find(
			[System.Security.Cryptography.X509Certificates.X509FindType]::FindByEnhancedKeyUsage,
			"1.3.6.1.5.5.7.3.2", # Client Authentication OID
			$true
		)
		return $clientCerts.Count -gt 0
	}
	finally
	{
		if ($userStore) { $userStore.Close() }
	}
}

$buttonTlsInstall.Add_Click({
		try
		{
			# First check if user wants to import a certificate
			$result = [System.Windows.Forms.MessageBox]::Show(
				"Would you like to import a client certificate?",
				"Certificate Import",
				[System.Windows.Forms.MessageBoxButtons]::YesNo,
				[System.Windows.Forms.MessageBoxIcon]::Question)
			
			if ($result -eq [System.Windows.Forms.DialogResult]::Yes)
			{
				if (-not (Import-UserCertificate))
				{
					$statusLabel.Text = "Certificate import cancelled or failed"
					$form.Refresh()
					Start-Sleep -Seconds 2
					return
				}
			}
			
			# Then verify we have a valid certificate
			if (-not (Test-UserCertificateAvailable))
			{
				$statusLabel.Text = "No valid client certificate found"
				$form.Refresh()
				Start-Sleep -Seconds 2
				$statusLabel.Text = "Install client cert in CurrentUser store"
				return
			}
			
			
			Add-Type -AssemblyName System.Configuration
			$statusLabel.Text = "Loading configuration..."
			$form.Refresh()
			
			$vpnName = [System.Configuration.ConfigurationManager]::AppSettings["vpnName"]
			$serverAddress = [System.Configuration.ConfigurationManager]::AppSettings["serverAddress"]
			$destinationPrefixesRaw = [System.Configuration.ConfigurationManager]::AppSettings["destinationPrefixes"]
			$caUrl = [System.Configuration.ConfigurationManager]::AppSettings["caUrl"]
			$crlUrl = [System.Configuration.ConfigurationManager]::AppSettings["crlUrl"]
			$pullCA = [System.Configuration.ConfigurationManager]::AppSettings["pullCA"] -eq "true"
			$pullCRL = [System.Configuration.ConfigurationManager]::AppSettings["pullCRL"] -eq "true"
			$useDnsSuffixInDnsRegistration = [System.Configuration.ConfigurationManager]::AppSettings["useDnsSuffixInDnsRegistration"] -eq "true"
			
			# Validate critical configuration values
			if (-not $vpnName) { throw "VPN name is not configured in settings." }
			if (-not $serverAddress) { throw "Server address is not configured in settings." }
			if (-not $destinationPrefixesRaw) { throw "Destination prefixes are not configured in settings." }
			
			$destinationPrefixes = $destinationPrefixesRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
			if (-not $destinationPrefixes) { throw "No valid destination prefixes found in settings." }
			
			$dnsSuffixesRaw = [System.Configuration.ConfigurationManager]::AppSettings["dnsSuffixes"]
			$dnsSuffixes = if ([string]::IsNullOrWhiteSpace($dnsSuffixesRaw))
			{
				@()
			}
			else
			{
				$dnsSuffixesRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
			}
			
			$statusLabel.Text = "Validating DNS suffixes..."
			$form.Refresh()
			if ($dnsSuffixes.Count -gt 0)
			{
				$invalidSuffixes = $dnsSuffixes | Where-Object { $_ -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$' }
				if ($invalidSuffixes)
				{
					$statusLabel.Text = "Invalid DNS suffix: " + ($invalidSuffixes -join ', ')
					$form.Refresh()
					Start-Sleep -Seconds 2
					$statusLabel.Text = "Ready"
					return
				}
			}
			
			# Dynamically determine certificate store based on admin status
			$isAdmin = Test-IsAdmin
			$storeLocation = if ($isAdmin) { "LocalMachine" }
			else { "CurrentUser" }
			$certStore = "Cert:\$storeLocation\Root"
			$caDest = if ($pullCA) { [System.IO.Path]::GetTempFileName() }
			else { $null }
			$crlDest = if ($pullCRL) { [System.IO.Path]::GetTempFileName() }
			else { $null }
			
			function Test-CertExists
			{
				param ([string]$thumbprint)
				$existingCerts = Get-ChildItem -Path $certStore | ForEach-Object { $_.Thumbprint.ToLower() }
				return $existingCerts -contains $thumbprint.ToLower()
			}
			
			if ($pullCA)
			{
				try
				{
					if (-not $caUrl) { throw "CA URL is not configured in settings." }
					if (-not (Request-AdminRights "CA certificate installation"))
					{
						throw "Administrator rights are required to install the CA certificate"
					}
					
					$statusLabel.Text = "Downloading CA certificate..."
					$form.Refresh()
					Invoke-WebRequest -Uri $caUrl -OutFile $caDest -UseBasicParsing -ErrorAction Stop
					if ((Get-Content $caDest -Raw).Length -eq 0)
					{
						throw "The downloaded CA file is empty. Check the URL or server response."
					}
					
					$certPem = Get-Content -Path $caDest -Raw
					$base64String = $certPem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
					while ($base64String.Length % 4 -ne 0) { $base64String += '=' }
					$certBytes = [System.Convert]::FromBase64String($base64String)
					$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
					$cert.Import($certBytes)
					
					if (Test-CertExists $cert.Thumbprint)
					{
						$statusLabel.Text = "CA cert " + $cert.Thumbprint + " already exists"
					}
					else
					{
						$statusLabel.Text = "Installing CA cert to $storeLocation..."
						$form.Refresh()
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", $storeLocation)
						$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
						$store.Add($cert)
						$store.Close()
						$statusLabel.Text = "CA cert " + $cert.Thumbprint + " installed"
					}
					$form.Refresh()
					Start-Sleep -Seconds 1
					if (Test-IsAdmin)
					{
						Write-Host "Setting certificate validation policy..."
						if (Set-CertificateValidationPolicy -caCertificate $cert)
						{
							Write-Host "Certificate validation policy set successfully."
						}
						else
						{
							Write-Warning "Failed to set certificate validation policy"
						}
					}
					else
					{
						Write-Host "Admin privileges required to set certificate validation policy."
					}
				}
				finally
				{
					if ($cert) { $cert.Dispose() }
					if ($store) { $store.Dispose() }
				}
			}
			
			if ($pullCRL)
			{
				try
				{
					if (-not $crlUrl) { throw "CRL URL is not configured in settings." }
					if (-not (Request-AdminRights "CA certificate installation"))
					{
						throw "Administrator rights are required to install the CA certificate"
					}
					$statusLabel.Text = "Downloading CRL..."
					$form.Refresh()
					Invoke-WebRequest -Uri $crlUrl -OutFile $crlDest -UseBasicParsing -ErrorAction Stop
					if ((Get-Content $crlDest -Raw).Length -eq 0)
					{
						throw "The downloaded CRL file is empty. Check the URL or server response."
					}
					
					try
					{
						$crlBytes = [System.IO.File]::ReadAllBytes($crlDest)
						$derPath = [System.IO.Path]::GetTempFileName()
						[System.IO.File]::WriteAllBytes($derPath, $crlBytes)
						& certutil -urlfetch -f $crlUrl | Out-Null
						$statusLabel.Text = "CRL fetched and cached"
						$form.Refresh()
						Start-Sleep -Seconds 1
						Remove-Item -Path $derPath -Force -ErrorAction SilentlyContinue
					}
					catch
					{
						$statusLabel.Text = "Failed to process CRL: " + $_.Exception.Message
						$form.Refresh()
						Start-Sleep -Seconds 2
						$statusLabel.Text = "Ready"
						return
					}
				}
				finally
				{
					if ($pullCA -and $caDest -and (Test-Path $caDest))
					{
						Remove-Item -Path $caDest -Force -ErrorAction SilentlyContinue
					}
					if ($pullCRL -and $crlDest -and (Test-Path $crlDest))
					{
						Remove-Item -Path $crlDest -Force -ErrorAction SilentlyContinue
					}
				}
			}
			
			# Rest of VPN installation code...
			$existingVpn = Get-VpnConnection -Name $vpnName -ErrorAction SilentlyContinue
			if ($existingVpn)
			{
				$statusLabel.Text = "Removing existing VPN..."
				$form.Refresh()
				Remove-VpnConnection -Name $vpnName -Force -ErrorAction SilentlyContinue
				Start-Sleep -Seconds 1
			}
			
			$statusLabel.Text = "Installing VPN..."
			$form.Refresh()
			Add-VpnConnection -Name $vpnName `
							  -ServerAddress $serverAddress `
							  -TunnelType IKEv2 `
							  -EncryptionLevel Maximum `
							  -AuthenticationMethod Eap `
							  -EapConfigXmlStream $eaptlsXmlContent `
							  -RememberCredential $False `
							  -DnsSuffixInDnsRegistration $useDnsSuffixInDnsRegistration `
							  -Force
			
			# Add delay to ensure VPN is fully registered
			Start-Sleep -Seconds 3
			
			if ($dnsSuffixes.Count -gt 0)
			{
				$statusLabel.Text = "Adding DNS suffixes: " + ($dnsSuffixes -join ', ')
				$form.Refresh()
				Start-Sleep -Milliseconds 500
				foreach ($dnsSuffix in $dnsSuffixes)
				{
					try
					{
						$statusLabel.Text = "Adding DNS suffix: $dnsSuffix"
						$form.Refresh()
						Add-VpnConnectionTriggerDnsConfiguration -ConnectionName $vpnName `
																 -DnsSuffix $dnsSuffix `
																 -Force `
																 -ErrorAction Stop
						$statusLabel.Text = "Added DNS suffix: $dnsSuffix"
						$form.Refresh()
						Start-Sleep -Milliseconds 500
					}
					catch
					{
						$statusLabel.Text = "Error adding DNS suffix " + $dnsSuffix + ": " + $_.Exception.Message
						$form.Refresh()
						Start-Sleep -Seconds 1
					}
				}
			}
			else
			{
				$statusLabel.Text = "No DNS suffixes to add"
				$form.Refresh()
				Start-Sleep -Seconds 1
			}
			
			$statusLabel.Text = "Setting IPsec configuration..."
			$form.Refresh()
			Set-VpnConnectionIPsecConfiguration -ConnectionName "$vpnName" `
					-AuthenticationTransformConstants SHA256 `
					-CipherTransformConstants GCMAES256 `
					-EncryptionMethod AES256 `
					-IntegrityCheckMethod SHA256 `
					-DHGroup ECP256 `
					-PfsGroup ECP256 `
					-PassThru `
					-Force
			
			$statusLabel.Text = "Adding VPN routes..."
			$form.Refresh()
			foreach ($prefix in $destinationPrefixes)
			{
				Add-VpnConnectionRoute -ConnectionName $vpnName -DestinationPrefix $prefix -PassThru -ErrorAction SilentlyContinue
			}
			
			Update-VpnList
			$statusLabel.Text = "VPN installed successfully"
			$form.Refresh()
			Start-Sleep -Seconds 1
			Update-VpnStatus
		}
		catch
		{
			$statusLabel.Text = "Installation failed: " + $_.Exception.Message
			$form.Refresh()
			Start-Sleep -Seconds 2
			$statusLabel.Text = "Ready"
		}
		finally
		{
			Update-VpnStatus
		}
	})

function Update-CACertificates
{
	param (
		[string]$caUrl,
		[string]$crlUrl
	)
	try
	{
		if ($caUrl)
		{
			Write-Host "Downloading CA certificate from $caUrl"
			$caTempFile = [System.IO.Path]::GetTempFileName()
			Invoke-WebRequest -Uri $caUrl -OutFile $caTempFile -UseBasicParsing -ErrorAction Stop
			Write-Host "CA certificate downloaded successfully"
		}
		if ($crlUrl)
		{
			Write-Host "Downloading CRL from $crlUrl"
			$crlTempFile = [System.IO.Path]::GetTempFileName()
			Invoke-WebRequest -Uri $crlUrl -OutFile $crlTempFile -UseBasicParsing -ErrorAction Stop
			Write-Host "CRL downloaded successfully"
		}
		return $true
	}
	catch
	{
		Write-Error "Error updating CA/CRL certificates: $_"
		return $false
	}
	finally
	{
		if ($caTempFile -and (Test-Path $caTempFile)) { Remove-Item -Path $caTempFile -Force }
		if ($crlTempFile -and (Test-Path $crlTempFile)) { Remove-Item -Path $crlTempFile -Force }
	}
}

# Tray Icon Setup
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
try {
    # Try to use a system icon instead
    $systemIcon = [System.Drawing.SystemIcons]::Application
    $form.Icon = $systemIcon
    $trayIcon.Icon = $systemIcon
}
catch {
    Write-Host "Cannot set application icon: $_" 
    # Just continue without an icon
}

$trayIcon.Visible = $true
$trayIcon.Text = "Advantive VPN Tool"

# Tray context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$contextMenu.Items.Add("Connect", $null, { Start-Process "rasphone" })
$contextMenu.Items.Add("Open", $null, {
		$form.Show()
		$form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
		$form.ShowInTaskbar = $true
		$form.BringToFront()
	})
$contextMenu.Items.Add("Exit", $null, {
		$script:allowExit = $true
		$trayIcon.Visible = $false
		$trayIcon.Dispose()
		$form.Close()
		[System.Windows.Forms.Application]::Exit()
	})

$trayIcon.ContextMenuStrip = $contextMenu

# Minimize to tray with status label feedback
$form.Add_Resize({
		if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized)
		{
			$statusLabel.Text = "Minimized to tray"
			$form.Refresh()
			Start-Sleep -Milliseconds 500
			$form.Hide()
			$form.ShowInTaskbar = $false
			$trayIcon.Visible = $true
		}
	})

$form.Add_FormClosing({
		param ($formSender,
			$e)
		if (-not $script:allowExit)
		{
			$e.Cancel = $true
			$statusLabel.Text = "Minimized to tray"
			$form.Refresh()
			Start-Sleep -Milliseconds 500
			$form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
			$form.Hide()
			$form.ShowInTaskbar = $false
			$trayIcon.Visible = $true
		}
	})

$trayIcon.Add_DoubleClick({
		$form.Show()
		$form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
		$form.ShowInTaskbar = $true
		$form.BringToFront()
		Update-VpnStatus
	})

# Timer for periodic updates
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.Add_Tick({ Update-VpnStatus })
$timer.Start()

# Initial VPN status update
Update-VpnStatus

# Run the application
[System.Windows.Forms.Application]::EnableVisualStyles()
try
{
	if ($null -eq $form)
	{
		throw "The form object is null or improperly initialized."
	}
	[System.Windows.Forms.Application]::Run($form)
}
catch
{
    Write-Error "An unexpected error occurred: $_"
    [System.Windows.Forms.MessageBox]::Show("An unexpected error occurred: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}
finally
{
	# Ensure resources are properly cleaned up
	if ($null -ne $trayIcon) {
		$trayIcon.Visible = $false
		$trayIcon.Dispose()
	}
	if ($null -ne $timer) {
		$timer.Stop()
		$timer.Dispose()
	}
}