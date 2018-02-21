function FinnaNafnNetkortsMedIpTolu{
    param(
        [Parameter(Mandatory=$true, HelpMessage="Sl��u inn t�lu.")]
        [string]$IPTala
        )
        (Get-NetIPAddress -IP $IPTala | Get-NetAdapter).Name
        if (!(Get-NetIPAddress -IP $IPTala | Get-NetAdapter).Name){
            $NKort = Write-Error -Message "Fann ekki netrkort me� ipt�lu $IPTala"
        }
        else{
            $NKort = (Get-NetIPAddress -IP $IPTala | Get-NetAdapter).Name
        }

        

}
$NKort = FinnaNafnNetkortsMedIpTolu -IPTala "169.254.*"
$NKort


# IP stillingar
Rename-NetAdapter -Name $NKort -NewName "LAN"
New-NetIPAddress -InterfaceAlias LAN -IPAddress 10.10.10.65 -PrefixLength 26
Set-DnsClientServerAddress -InterfaceAlias LAN -ServerAddresses 127.0.0.1

# Setja inn ADDS role
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools
# Setja upp domain controllerinn
Install-ADDSForest -DomainName ddp-elas.local -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force)

# setja inn DHCP role
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Add-DhcpServerv4Scope -Name scope1 -StartRange 10.10.10.86 -EndRange 10.10.10.126 -SubnetMask 255.255.255.192
Set-DhcpServerv4OptionValue -DnsServer 10.10.10.65 -Router 10.10.10.65
Add-DhcpServerInDC -DnsName $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)


#Finna Domain: $env:USERDNSDOMAIN
 
# Folders
 
New-ADOrganizationalUnit -Name Notendur -ProtectedFromAccidentalDeletion $false
$grunnOUPath = (Get-ADOrganizationalUnit -Filter { name -like 'Notendur' }).DistinguishedName
New-ADGroup -Name NotendurGRP -Path $grunnOUPath -GroupScope Global
$notendur = Import-Csv .\Verkefni2_notendur_u.csv
 
foreach($n in $notendur){
    $deild = $n.deild
    if(-not(Get-ADOrganizationalUnit -Filter { name -like $deild })) {
        New-ADOrganizationalUnit -Name $deild -path $grunnOUPath -ProtectedFromAccidentalDeletion $false
        New-ADGroup -Name $deild -Path $("OU=" + $deild + "," + $grunnOUPath) -GroupScope Global
        Add-ADGroupMember -Identity NotendurGRP -Members $deild
        #b�a til m�ppu fyrir deild og share-a henni
        new-item C:\gogn\$deild -ItemType Directory
        $rettindi = Get-Acl -Path C:\gogn\$deild
        $nyrettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\" + $deild),"Modify","Allow")
        $rettindi.AddAccessRule($nyrettindi)
        Set-Acl -Path C:\gogn\$deild $rettindi
        New-SmbShare -Name $deild -Path C:\gogn\$deild -FullAccess $env:USERDOMAIN\$deild, administrators
 
    }
 
    New-ADUser -Name $n.nafn -DisplayName $n.nafn -GivenName $n.fornafn -Surname $n.eftirnafn -SamAccountName $n.notendanafn -UserPrincipalName $($n.notendanafn + "@" + $env:USERDNSDOMAIN) -Path $("OU=" + $deild + "," + $grunnOUPath) -AccountPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force) -Enabled $true
   
    Add-ADGroupMember -Identity $deild -Members $n.notendanafn
}
 
#B� til m�ppuna
new-item C:\gogn\sameign -ItemType Directory
 
#s�ki n�verandi r�ttindi
$rettindi = Get-Acl -Path C:\gogn\sameign
 
#b� til �au r�ttindi sem �g �tla a� b�ta vi� m�ppuna
$nyrettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\sameign"),"Modify","Allow")
#Hver � a� f� r�ttindin, hva�a r�ttindi � vi�komandi a� f�, erum vi� a� leyfa e�a banna (allow e�a deny)
 
#b�ti n�ju r�ttindunum vi� �au sem �g s�tti ��an
$rettindi.AddAccessRule($nyrettindi)
 
#Set r�ttindin aftur � m�ppuna
Set-Acl -Path C:\gogn\sameign $rettindi
 
#Share-a m�ppunni
New-SmbShare -Name Sameign -Path C:\gogn\sameign -FullAccess $env:USERDOMAIN\NotendurGRP, administrators
