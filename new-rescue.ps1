<#
.SYNOPSIS
    Creates a Rescue VM and attaches the OS Disk of the problem VM to this intermediate rescue VM.

.DESCRIPTION
    This script automates the creation of Rescue VM to enable fixing of OS disk issues related to a problem VM.
    In such cases it is a common practice to recover the problem VM by performing the following steps. These are the steps that are performed by the script.
        -Stops the problem VM
        -Take a snapshot of the OS Disk
        -Create a Temporary Rescue VM
        -Attach the OS Disk to the Rescue VM
    -Starts the Rescue VM
    -RDPs to RescueVM (For Windows)

.PARAMETER VmName
    This is a mandatory Parameter, Name of the problem VM that needs to be recovered.

.PARAMETER ResourceGroupName
    This is a mandatory Parameter, Name of the resource group the problem VM belongs to.

.PARAMETER SubscriptionId
    Optional Parameter, SubscriptionID the VM belongs to.

.PARAMETER showErrors
    Optional Parameter. By default it is set to true, so it displays all errors thrown by PowerShell in the console, if set to False it runs in silentMode.

.PARAMETER prefix
    Optional Parameter. By default the new Rescue VM and its resources are all created under a resource group named same as the original resource group name with a prefix of 'rescue', however the prefix can be changed to a different value to override the default 'rescue'

.PARAMETER UserName
    Optional Parameter. Allows to pass in the user name of the rescue VM during its creation, by default during case creation it will prompt

.PARAMETER Password
    Optional Parameter. Allows to pass in the password of the rescue VM during its creation, by default t will prompt for password during its creation

.PARAMETER AllowManagedVM
    Optional Parameter. This allows the script to support Managed VM's also, however prior to that the SubscriptionID needs to be whitelisted to be able to use the OS Disk Swap feature formanaged VM's.

.PARAMETER Sku
    Optional Parameter. Allows to pass in the SKU of the preferred image of the OS for the Rescue VM

.PARAMETER Offer
    Optional Parameter. Allows to pass in the Offer of the preferred image of the OS for the Rescue VM

.PARAMETER Publisher
    Optional Parameter. Allows to pass in the Publisher of the preferred image of the OS for the Rescue VM

.PARAMETER Version
    Optional Parameter. Allows to pass in the Version of the preferred image of the OS for the Rescue VM

.EXAMPLE
    Example using all the mandatory fields:

    $scriptResult = .\New-AzureRMRescueVM.ps1 -resourceGroupName sujtemp -VmName sujnortheurope -subscriptionId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

.EXAMPLE
    Examples with optional parametersm in this example it will create the rescue VM with RedHat installed

    $scriptResult = .\New-AzureRMRescueVM.ps1 -VmName ubuntu -resourceGroupName portalLin -subscriptionId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Publisher RedHat -Offer RHEL -Sku 7.3 -Version 7.3.2017090723 -prefix rescuered

.EXAMPLE
    $scriptResult = .\New-AzureRMRescueVM.ps1 -resourceGroupName sujtemp -VmName sujnortheurope -subscriptionId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex2"

.EXAMPLE
    Example for managed disk VM:

    $scriptResult =  .\New-AzureRMRescueVM.ps1 -resourceGroupName sujasrg -VmName sujunmanagedP -subscriptionId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex0011"

.EXAMPLE
    Example for managed disk VM

    $scriptResult = .\New-AzureRMRescueVM.ps1 -resourceGroupName recoveryVMRg -VmName recovmtestmg  -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex2"

.EXAMPLE
    Example for marketplace image with Plan

    $scriptResult = .\New-AzureRMRescueVM.ps1 -resourceGroupName recoverytest -VmName datasciencevm  -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex17" -AllowManagedVM

.EXAMPLE
    Using a VM created from a custom image:

    $scriptResult =  .\New-AzureRMRescueVM.ps1 -resourceGroupName testvmrecovery2 -VmName win2016custom  -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex18"

.EXAMPLE
    Using a VM Unmanaged Windows VM

    $scriptResult =  .\New-AzureRMRescueVM.ps1 -resourceGroupName testvmrecovery2 -VmName sujUNManagedvm  -UserName "sujasd" -Password "XPa55w0rrd12345" -prefix "rescuex48"

.NOTES
    Name: New-AzureRMRescueVM.ps1

    To get help on the below script run get-help .\New-AzureRMRescueVM.ps1

#>

param(

        [Parameter(mandatory=$true)]
        [String]$vmName,

        [Parameter(mandatory=$true)]
        [String]$ResourceGroupName,

        [Parameter(mandatory=$true)]
        [String]$Encryption_type,

        [Parameter(mandatory=$true)]
        [String]$rescueVMName,

       
        [Parameter(mandatory=$true)]
        [String]$rescuevm_require_public_ip,


        [Parameter(mandatory=$false)]
        [String]$subscriptionId,

        [Parameter(mandatory=$true)]
        [String]$rescuevmusername,

        [Parameter(mandatory=$true)]
        [String]$rescuevmpassword,

        [Parameter(mandatory=$false)]
        [String]$UserName,

        [Parameter(mandatory=$false)]
        [Bool]$showErrors=$true,

        [Parameter(mandatory=$false)]
        [String]$prefix = 'rescue',

        [Parameter(mandatory=$false)]
        [String]$Sku,

        [Parameter(mandatory=$false)]
        [String]$Offer,

        [Parameter(mandatory=$false)]
        [String]$Publisher,

        [Parameter(mandatory=$false)]
        [String]$Version,

        [switch]$AllowManagedVM = $true
     )


Write-Host 'Checking Disk Encryption Status' -ForegroundColor DarkGreen

$Encryption_status=$(Get-AzureRmVmDiskEncryptionStatus -ResourceGroupName $ResourceGroupName -VMName $vmName | grep -i OsVolumeEncrypted | awk -F":" '{print $2}' | sed 's/^ *//')

IF ($Encryption_status -ne "Encrypted")

{
    Write-Host "############### OS Disk is not Encrypted. Cannot proceed with the script ##################" -ForegroundColor DarkGreen
#exit

}

ELSE

{
    Write-Host "################# OS Disk is Encrypted. Proceeding further execution. #####################" -ForegroundColor DarkGreen

}


$script:scriptStartTime = (get-date).ToUniversalTime()
$timestamp = get-date $script:scriptStartTime -f yyyyMMddHHmmss
$scriptPath = split-path -path $MyInvocation.MyCommand.Path -parent
$scriptName = (split-path -path $MyInvocation.MyCommand.Path -leaf).Split('.')[0]
$logFile = "$scriptPath\$($scriptName)_$($vmName)_$($timestamp).log"
$restoreCommandFile = "Restore_" + $vmName + ".ps1"
set-location $scriptPath
$commonFunctionsModule = "$scriptPath\Common-Functions.psm1"

#Import-Module Common-Functions -ArgumentList $logFile -ErrorAction Stop
if (get-module Common-Functions)
{
    remove-module -name Common-Functions
}
import-module -Name $commonFunctionsModule -ArgumentList $logFile -ErrorAction Stop

$EventName = "Started"
$scriptVersion = "1.0.0"
$scriptRunId = [System.Guid]::NewGuid()
$Message = "Started execution of the script"
LogToAppInsight -EventName $EventName -scriptname $MyInvocation.MyCommand.Name -Command $MyInvocation.Line -Scriptversion $scriptVersion -Message $Message -RunID $scriptRunId


#write-log "Log file: $logFile"
#write-log $MyInvocation.Line -logOnly



#Checks to see if AzureRM is available
if (-not (get-module -ListAvailable -name 'AzureRM.Profile') -and (-not $env:ACC_CLOUD))
{
    $message = "[Error] Azure PowerShell not installed. Either install Azure PowerShell from https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps or use Cloud Shell PowerShell at https://shell.azure.com/powershell"
    write-log $message -color red
    $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
    return $scriptResult
}

if (-not (Get-AzureRmContext).Account)
{
    $null = Login-AzureRmAccount
}

if (-not $subscriptionId)
{
    write-log "[Running] Getting authentication context"
    $authContext = Get-AzureRmContext
    if (-not $authContext.Subscription.Id)
    {
        $message = "[Error] Unable to determine subscription ID. Run the script again using -SubscriptionID to specify the subscription ID."
        write-log $message -color red
        $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
        return $scriptResult
    }
}
else
{
    #Set the context to the correct subscription ID
    write-log "[Running] Setting context to subscriptionId $subscriptionId"
    $authContext = Set-AzureRmContext -SubscriptionId $subscriptionId
    write-log $authContext -logOnly
    if (-not $authContext.Subscription.Id)
    {
        $message = "[Error] Unable to set context to subscription ID $subscriptionId. Run Login-AzureRMAccount and then try the script again."
        write-log $message -color red
        $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
        return $scriptResult
    }
}
$subscriptionId = $authContext.Subscription.Id
$subscriptionName = $authcontext.Subscription.Name
$accountId = $authContext.Account.Id
$accountType = $authContext.Account.Type
$tenantId = $authContext.tenant.Id
$environmentName = $authContext.Environment.Name
write-log "[Success] Using subscriptionId: $subscriptionId, subscriptionName: $subscriptionName" -color green
write-log "AccountId: $accountId" -logOnly
write-log "AccountType: $accountType" -logOnly
write-log "TenantId: $tenantId" -logOnly
write-log "Environment: $environmentName" -logOnly

# Step 1 Get VM object
write-log "[Running] Get-AzureRmVM -resourceGroupName $resourceGroupName -Name $vmName"
try
{
    $vm = Get-AzureRmVM -ResourceGroupName $resourceGroupName -Name $vmName -ErrorAction Stop -WarningAction SilentlyContinue
}
catch
{
    $message = "[Error] Problem VM $vmName not found in resource group $resourceGroupName in subscription $subscriptionId. Verify the vmName, resourceGroupName, and subscriptionId and run the script again."
    write-log $message -color red
    write-log "Exception Type: $($_.Exception.GetType().FullName)" -logOnly
    write-log "Exception Message: $($_.Exception.Message)" -logOnly
    $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
    return $scriptResult
}
write-log "`$vm: $vm" -logOnly

if (-not (SupportedVM -vm $vm -AllowManagedVM $AllowManagedVM))
{
    $message = "[Error] Problem VM $($vm.name) is not supported."
    write-log $message -color red
    $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
    return $scriptResult
}

write-log "[Success] Found problem VM $($vm.Name)" -color green

if ($vm.StorageProfile.OsDisk.ManagedDisk)
{
    $managedVM = $true
}
else
{
    $managedVM = $false
}

write-log "[Running] Getting OsType for problem VM $vmName"
if ($vm.StorageProfile.OsDisk.OsType -eq 'Windows')
{
    $windowsVM = $true
}
else
{
    $windowsVM = $false
}
write-log "[Success] Problem VM $vmName OsType is $($vm.StorageProfile.OsDisk.OsType)" -color green


# Step 2 Stop problem VM
$stopped = StopTargetVM -resourceGroupName $resourceGroupName -VmName $vmName -Force
write-log "`$stopped: $stopped" -logOnly
if (-not $stopped)
{
    $message = "[Error] Unable to stop problem VM $vmName"
    write-log $message -color red
    $scriptResult = Get-ScriptResultObject -scriptSucceeded $false -rescueScriptCommand $MyInvocation.Line -FailureReason $message -Scriptversion $scriptVersion -RunID $scriptRunId
    return $scriptResult
}

$vm_details=$(az vm show -g $resourceGroupName -n $vmName)
$offer=$(echo $vm_details | jq ".storageProfile.imageReference.offer")
$Publisher=$(echo $vm_details | jq ".storageProfile.imageReference.publisher")
$sku=$(echo $vm_details | jq ".storageProfile.imageReference.sku")
$Version=$(echo $vm_details | jq ".storageProfile.imageReference.version")
$location=$(echo $vm_details | jq '.location' | tr -d '"')

########## "If source VM is RHEL7.7 rescue VM will be creatd with RHEL 7.4 image to avoid duplication with Volume Groups"
IF ($sku -eq '"7-LVM"')
         {
       $sku="7.4"
         }

$urn=$publisher,$offer,$sku,$version
$image_urn=$(echo $urn | xargs | sed 's/ /:/g')
$os_disk=$(echo $vm_details| jq ".storageProfile.osDisk")
$disk_uri=$(echo $os_disk | jq ".managedDisk.id")
$disk_uri=$($disk_uri -replace '"', "")
$os_type=$(echo $vm_details | jq .storageProfile.osDisk.osType)

Write-Host '################## Generating Snapshot of problematic VM's OS Disk ####################' -ForegroundColor DarkGreen
$time=date +%d-%m-%Y-%T
$source_disk_name=$(echo $disk_uri | awk -F"/" '{print $NF}')
$snapshot_name=$((echo $disk_uri | awk -F"/" '{print $NF}') -replace '_', "-")
$snapshot_name=$((echo $snapshot_name | cut -c1-10 ))
$snapshot_name=$((echo $snapshot_name-snap-$time) -replace ":","-")
$target_disk_name=$((echo $disk_uri | awk -F"/" '{print $NF}') -replace '_', "-")
$target_disk_name=$((echo $target_disk_name | cut -c1-10))
$target_disk_name=$((echo $target_disk_name-copy-$time) -replace ":", "-")
az snapshot create -g $resource_group $resourceGroupName -n $snapshot_name --source $source_disk_name -l $location

Write-Host '################### Creating disk from snapshot ####################' -ForegroundColor DarkGreen
$snapshotId=$(az snapshot show --name $snapshot_name --resource-group $resourceGroupName --query [id] -o tsv)
$disk_type=$(az disk list --output table | grep -i $source_disk_name | awk '{print $4}')
az disk create --resource-group $resourceGroupName --name $target_disk_name -l $location --sku $disk_type --source $snapshotId


Write-Host '################### Creating Rescue VM ####################' -ForegroundColor DarkGreen

IF ($rescuevm_require_public_ip -eq "YES")
{
    IF ($Publisher -eq "null")
    {
        IF ($os_type -eq '"Windows"')
         {
           Write-Host "################ ######### VM seems to be created from specialised Disk."    
           $image = Read-Host 'Enter image name. ( Valid Image names are Win2019Datacenter, Win2016Datacenter, Win2012R2Datacenter, Win2012Datacenter, Win2008R2SP1 )'
         }

        ELSE
         {
    Write-Host "################ ######### VM seems to be created from specialised Disk."
    $image = Read-Host 'Enter image name. ( Valid Image names are RHEL,SLES,UBUNTULTS,CENTOS )'
         IF ($image -eq "RHEL")   
           {
           $image_urn="RedHat:RHEL:7.4:latest"
     az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image $image_urn --storage-sku Standard_LRS
           }

         ELSE
         {
   az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image $image --storage-sku Standard_LRS
         }
  }
 }
        ELSE
        {
        az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image $image_urn --storage-sku Standard_LRS
        }
}

IF ($rescuevm_require_public_ip -eq "NO")
{
   IF ($Publisher -eq "null")
    {
      IF ($os_type -eq '"Windows"')
         {
           Write-Host "################ ######### VM seems to be created from specialised Disk."           
           $image = Read-Host 'Enter image name. ( Valid Image names are Win2019Datacenter, Win2016Datacenter, Win2012R2Datacenter, Win2012Datacenter, Win2008R2SP1 )'
         }

     ELSE
     {
    Write-Host "################ ######### VM seems to be created from specialised Disk."
    $image = Read-Host 'Enter image name. ( Valid Image names are RHEL,SLES,UBUNTULTS,CENTOS )'     

     IF ($image -eq "RHEL")
           {
           $image_urn="RedHat:RHEL:7.4:latest"
    az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image $image_urn --storage-sku Standard_LRS --public-ip-address '""'
           }

   ELSE
   {
   az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image "$image" --storage-sku Standard_LRS --public-ip-address '""'
   }
  }
 }
   ELSE
   {
   az vm create --name  $rescueVMName -g $resourceGroupName --location $location --admin-username $rescuevmusername --admin-password $rescuevmpassword --image "$image_urn" --storage-sku Standard_LRS --public-ip-address '""'
   }
}

$rescuevmpubip=$(az vm show -d -g $resourceGroupName -n $rescueVMName --query publicIps -o tsv)
$rescuevmprivip=$(az vm show -d -g $resourceGroupName -n $rescueVMName --query privateIps -o tsv)

$disk= Get-AzureRMDisk -ResourceGroupName $ResourceGroupName -DiskName $source_disk_name
$keyvaulturl=$disk.EncryptionSettingsCollection.EncryptionSettings.diskencryptionkey.SecretUrl
echo $keyvaulturl
$kekurl=$disk.EncryptionSettingsCollection.EncryptionSettings.KeyEncryptionKey.KeyUrl
#$Encryption_type=$disk.EncryptionSettingsCollection.Enable


$rgName=$ResourceGroupName
$vmName=$vmName
$vmSize=$(echo $vm_details | grep -i "vmsize" | awk -F": " '{print $2}')
$vmc = New-AzureRmVmConfig -VMName $vmName -VMSize $vmSize
$interface=az vm show -g $ResourceGroupName -n $vmName | grep -i "networkinterfaces/" | head -1 | awk -F"/" '{print $NF}' | awk -F"," '{print $1}'
$networkinterface=$($interface -replace '"', "")
$nic = Get-AzureRmNetworkInterface -Name "$networkinterface" -ResourceGroupName $rgName
Add-AzureRmVmNetworkInterface -VM $vmc -Id $nic.Id
$manageddiskid = Get-AzureRMDisk -ResourceGroupName $ResourceGroupName -DiskName $target_disk_name | grep -i Id | grep -i disks | awk -F": " '{print $2}'
$KeyVaultName=echo $keyvaulturl | awk -F".vault.azure.net" '{print $1}' | awk -F"//" '{print $2}'
$diskencryptionkeyvaultid= Get-AzureRmKeyVault -VaultName $KeyVaultName | grep -i "Resource ID" | awk -F": " '{print $2}'
$diskencryptionkeyurl = $keyvaulturl
$keyvaultresourceid=$diskencryptionkeyvaultid
$keyencryptionkeyurl=$kekurl
echo $diskencryptionkeyvaulturl


$rgKeyName=Get-AzureRmKeyVault -VaultName $KeyVaultName | grep -i "resource group" | awk -F": " '{print $2}'

$KeyVault = Get-AzureRmKeyVault -VaultName $KeyVaultName -ResourceGroupName $rgKeyName;
$diskEncryptionKeyVaultUrl = $KeyVault.VaultUri;
$KeyVaultResourceId = $KeyVault.ResourceId;

$ADEKeyName=echo $kekurl | awk -F "/" '{print $5}'
$VolumeType = 'Data';


IF ($Encryption_type -eq "Single")
{
    Write-Host "################# Encryption type is single ###############" -ForegroundColor DarkGreen

Write-Host '########################### Attaching copy of OS disk to rescue VM #######################' -ForegroundColor DarkGreen
$DestVMName= "$rescueVMName"
$DestVMRG= "$resourceGroupName"
$OSDisk = Get-AzureRmDisk -ResourceGroupName $DestVMRG -DiskName $target_disk_name
$vm = get-AzureRMVM -ResourceGroupName $DestVMRG -Name $DestVMName
Add-AzureRmVMDataDisk -VM $vm -Name $target_disk_name -ManagedDiskId $osDisk.Id -Caching None -Lun 3 -CreateOption Attach
Update-AzureRMVM -VM $vm -ResourceGroupName $DestVMRG
$sequenceVersion = [Guid]::NewGuid()

<#
$val="@"
$con=":"
$path="/tmp/secret.bek"
sed -i '/secretUrl=/d' key.ps1
sed -i '/secretFilePath=/d' key.ps1
sed -i  '/kekUrl=/d' key.ps1
sed -i '"1i$secretUrl='"'$keyvaulturl'"'"' key.ps1
sed -i '"2i$secretFilePath='"'$path'"'"' key.ps1
sed -i '"3i$kekUrl='"'$kekurl'"'"' key.ps1
sed -i '/Copying secret.bek/d' key.ps1
sed -i '/scp -pr/d' key.ps1

echo "Write-Host 'Copying secret.bek to rescue VM. Please provide rescue VMs password' -ForegroundColor Black -BackgroundColor DarkGreen" >> key.ps1
echo "scp -pr $path  $rescuevmusername$val$rescuevmip$con$path" >> key.ps1

./key.ps1
#>

IF ( !$kekurl )
{
  IF ($os_type -eq '"Windows"')
  {
   echo $os_type
    $VolumeType="ALL"
    Write-Host "####################### Single pass encryption without KEK #####################"  -ForegroundColor DarkGreenSet-AzureRmVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $rescueVMName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId -VolumeType $VolumeType -SequenceVersion $sequenceVersion -skipVmBackup;
  }
  ELSE{

Write-Host "####################### Single pass encryption without KEK #####################"  -ForegroundColor DarkGreen
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $rescueVMName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId -VolumeType $VolumeType -SequenceVersion $sequenceVersion -skipVmBackup;
     }
}
ELSE
{
   IF ($os_type -eq '"Windows"')
  {
  echo $os_type
  $VolumeType="ALL" 
  Write-Host "################ Single pass encryption with KEK #######################" -ForegroundColor DarkGreen
  $key = Get-AzureKeyVaultKey -VaultName $KeyVaultName -Name $ADEKeyName
  $keyencryptionkeyurl=$key.Id
  Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $rescueVMName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId -KeyEncryptionKeyUrl $keyencryptionkeyurl -KeyEncryptionKeyVaultId $KeyVaultResourceId -VolumeType $VolumeType -SequenceVersion $sequenceVersion -skipVmBackup;
  }
  ELSE
  {

Write-Host "################ Single pass encryption with KEK #######################" -ForegroundColor DarkGreen

$key = Get-AzureKeyVaultKey -VaultName $KeyVaultName -Name $ADEKeyName
$keyencryptionkeyurl=$key.Id


# With KEK
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $rescueVMName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId -KeyEncryptionKeyUrl $keyencryptionkeyurl -KeyEncryptionKeyVaultId $KeyVaultResourceId -VolumeType $VolumeType -SequenceVersion $sequenceVersion -skipVmBackup;
  }
}

IF ($os_type -eq '"Windows"')
  {
Write-Host "#################### Copy of OS disk is successfully attached to rescue VM #####################"."
Write-Host "################ Below are your Rescue VM details #################""
RescueVM Name : $rescueVMName
Rescue VM Public IP : $rescuevmpubip
Rescue VM Private IP : $rescuevmprivip
Username : $rescuevmusername
Password : $rescuevmpassword" -ForegroundColor DarkGreen
exit
  }
  ELSE
  {

Write-Host "#################### Copy of OS disk is successfully attached to rescue VM #####################". Please execute below commands on rescue VM to mount the OS disk. The disk order may change since the VM reboots after enabling extension please validate the disk order in lsblk, if there is a change then please modify /dev/sdc with /dev/sdd"
#mkdir /{investigateboot,investigateroot}
#mount -o nouuid  /dev/sdc1 /investigateboot
#Use the below command to open the crypts lock for the osdisk.
#cryptsetup luksOpen --key-file /mnt/azure_bek_disk/LinuxPassPhraseFileName --header /investigateboot/luks/osluksheader /dev/sdc2 investigateosencrypt 
#mount -o nouuid /dev/mapper/investigateosencrypt /investigateroot" -ForegroundColor Black -BackgroundColor DarkYellow

Write-Host "################ Below are your Rescue VM details #################""

RescueVM Name : $rescueVMName 
Rescue VM Public IP : $rescuevmpubip
Rescue VM Private IP : $rescuevmprivip
Username : $rescuevmusername
Password : $rescuevmpassword" -ForegroundColor DarkGreen

exit
  }
}

IF ($Encryption_type -eq "dual")

{

Write-Host "################## Encryption type is dual ##################" -ForegroundColor DarkGreen

Write-Host '########################### Removing encryption settings from Disk and attaching it to rescue VM #######################' -ForegroundColor DarkGreen
#$rgName = "testrg"
#$osDiskName = " copiedmanagedisk"
New-AzureRmDiskUpdateConfig -EncryptionSettingsEnabled $false |Update-AzureRmDisk -diskName $target_disk_name -ResourceGroupName $resourceGroupName
$DestVMName= "$rescueVMName"
$DestVMRG= "$resourceGroupName"
$OSDisk = Get-AzureRmDisk -ResourceGroupName $DestVMRG -DiskName $target_disk_name
$vm = get-AzureRMVM -ResourceGroupName $DestVMRG -Name $DestVMName
Add-AzureRmVMDataDisk -VM $vm -Name $target_disk_name -ManagedDiskId $osDisk.Id -Caching None -Lun 3 -CreateOption Attach
Update-AzureRMVM -VM $vm -ResourceGroupName $DestVMRG


Write-Host "############ Migrating BEK Volume to Rescue VM ###################" -ForegroundColor DarkGreen

#$SourceVMName = "redhatmanaged"
#$SourceVMRG = "encryption"
#$DestVMName = "rhelteste"
#$DestVMRG = "encryption"
#Stop-AzureRmVM -ResourceGroupName $SourceVMRG -Name $SourceVMName –Force
$SourceVM = Get-AzureRmVM -ResourceGroupName $resourceGroupName -VMName $vmName
$DestVM = Get-AzureRmVM -ResourceGroupName $resourceGroupName -VMName $rescueVMName
$DestVM.StorageProfile.OsDisk.EncryptionSettings = $SourceVM.StorageProfile.OsDisk.EncryptionSettings

Update-AzureRmVM -ResourceGroupName $resourceGroupName -VM $DestVM

echo "###############################################"

write-Host "Copy of OS disk is successfully attached to rescue VM. Please refer CSS wiki page https://www.csssupportwiki.com/index.php/curated:Azure/Virtual_Machine/Features/Disk_Encryption/TSG/General_troubleshooting_for_encrypted_managed_disk#Method_1_2"  and refer Troubleshooting using ADE Dual-Pass --> Method 1 point no 9 which consists of the below commands on rescue VM to mount the OS disk. Once Troubleshooting is done Please refer point no 10 and 11 for for recreating and installing the ADE extension respectively"

# mkdir /{investigatekey,investigateboot,investigateroot}
# mount /dev/sdc1 /investigatekey
# mount -o nouuid /dev/sdd1 /investigateboot
# cryptsetup luksOpen --key-file /investigatekey/LinuxPassPhraseFileName --header /investigateboot/luks/osluksheader /dev/sdd2 investigateosencrypt
# mount -o nouuid /dev/mapper/investigateosencrypt /investigateroot/" -ForegroundColor Black -BackgroundColor DarkYellow 

Write-Host "Below are your Rescue VM details""

RescueVM Name : $rescueVMName
Rescue VM Public IP : $rescuevmpubip
Rescue VM Private IP : $rescuevmprivip
Username : $rescuevmusername
Password : $rescuevmpassword" -ForegroundColor DarkGreen

$kekurl=echo "$keyencryptionkeyurl" | sed 's/:443//g'

IF ( !$kekurl )
{
Write-Host "####################### Dual pass encryption without KEK #####################"  -ForegroundColor DarkGreen

Write-Host "####################### Delete the old VM and use the below parameters to recreate the VM after troubleshooting #####################  

 $rgName=""$rgName""
 $location="$location"
 $vmName=""$vmName""
 $vmSize="$vmSize"
 $networkinterface=""$networkinterface""
 $manageddiskid=""$manageddiskid""
 $diskencryptionkeyvaultid=""$diskencryptionkeyvaultid""
 $diskencryptionkeyvaulturl=""$diskencryptionkeyurl""
 $keyvaultresourceid=""$diskencryptionkeyvaultid""
 $keyencryptionkeyurl=""$kekurl""" -ForegroundColor Black -BackgroundColor DarkYellow

}
ELSE
{
Write-Host "################ Dual pass encryption with KEK #######################" -ForegroundColor DarkGreen

Write-Host "####################### Delete the old VM and use the below parameters to recreate the VM after troubleshooting #####################

 "'$rgName'"=""$rgName""
 "'$location'"="$location"
 "'$vmName'"=""$vmName""
 "'$vmSize'"="$vmSize"
 "'$networkinterface'"=""$networkinterface""
 "'$vmc'" = "'New-AzureRmVmConfig -VMName $vmName -VMSize $vmSize'"
 "'$nic = Get-AzureRmNetworkInterface -Name "$networkinterface" -ResourceGroupName $rgName'"
 "'Add-AzureRmVmNetworkInterface -VM $vmc -Id $nic.Id'"
 "'$manageddiskid'"=""$manageddiskid""
 "'$diskencryptionkeyvaultid'"=""$diskencryptionkeyvaultid""
 "'$diskencryptionkeyvaulturl'"=""$diskencryptionkeyurl""
 "'$keyvaultresourceid'"=""$diskencryptionkeyvaultid""
 "'$keyencryptionkeyurl'"=""$kekurl""
  Set-AzureRmVmOSDisk -VM "'$vmc'" -ManagedDiskId "'$manageddiskid'"   -DiskEncryptionKeyUrl "'$diskencryptionkeyvaulturl'" -DiskEncryptionKeyVaultId "'$diskencryptionkeyvaultid'" -KeyEncryptionKeyUrl "'$keyencryptionkeyurl'" -KeyEncryptionKeyVaultId "'$keyvaultresourceid'" -Linux -CreateOption Attach
 New-AzureRmVm -ResourceGroupName "'$rgName'" -Location "'$location'" -VM "'$vmc'"" -ForegroundColor Black -BackgroundColor DarkYellow
 

}

exit

}

