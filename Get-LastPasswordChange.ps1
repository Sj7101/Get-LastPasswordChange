function Get-LastPasswordChange {
    param (
        [string[]]$Usernames,          # List of usernames to query
        [string[]]$Domains,            # List of domains to query
        [string]$OutputFilePath = ""   # Optional: Path to save the result as a CSV file
    )

    # Ensure Active Directory module is imported
    if (-not (Get-Module -ListAvailable -Name "ActiveDirectory")) {
        Write-Error "Active Directory module is not installed or available."
        return
    }

    # Initialize an array to hold results
    $results = @()

    # Loop through each domain and each user
    foreach ($domain in $Domains) {
        foreach ($username in $Usernames) {
            try {
                # Get the AD user object from the specified domain
                $user = Get-ADUser -Identity $username -Server $domain -Properties pwdLastSet
                
                # Convert pwdLastSet from AD format to DateTime
                $pwdLastSetDate = [datetime]::FromFileTime($user.pwdLastSet)
                
                # Create a result object
                $results += [pscustomobject]@{
                    Username        = $username
                    Domain          = $domain
                    LastPasswordSet = $pwdLastSetDate
                }
            } catch {
                Write-Warning "Failed to retrieve password change date for user '$username' in domain '$domain'."
            }
        }
    }

    # Output results to console or CSV file
    if ($OutputFilePath) {
        $results | Export-Csv -Path $OutputFilePath -NoTypeInformation
        Write-Output "Results saved to $OutputFilePath."
    } else {
        $results
    }
}

<#
#Explanation:
Parameters:

Usernames: An array of usernames for whom the last password change date will be retrieved.
Domains: An array of domain names (or domain controllers) to query.
OutputFilePath: Optional. If provided, the results will be saved to a CSV file at the specified path. Otherwise, results are printed to the console.
Active Directory Module:
The function uses the Active Directory PowerShell module, specifically the Get-ADUser cmdlet, to retrieve the pwdLastSet attribute for each user. This attribute stores the date and time of the last password change in Active Directory.

Error Handling:
The function includes a try/catch block to handle errors, such as when a user or domain is not found or the user does not exist in the specified domain.

Examples
#Get Password Change Dates for a List of Users Across Multiple Domains:
$usernames = @("user1", "user2", "user3")
$domains = @("domain1.com", "domain2.com")
Get-LastPasswordChange -Usernames $usernames -Domains $domains

#Save Results to a CSV File:
$usernames = @("user1", "user2", "user3")
$domains = @("domain1.com", "domain2.com")
Get-LastPasswordChange -Usernames $usernames -Domains $domains -OutputFilePath "C:\path\to\results.csv"

#Requirements:
Active Directory Module: The script requires the Active Directory PowerShell module, which can be installed as part of the Remote Server Administration Tools (RSAT) or on domain-joined machines.

Permissions: The user running the script must have permission to query Active Directory objects in the specified domains.

#>