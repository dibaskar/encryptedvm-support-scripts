<<<<<<< HEAD
# Please note : This powershell script was created from https://github.com/Azure/azure-support-scripts/tree/master/VMRecovery/ResourceManager which was written by Windows PG for rescue VM creation for non encrypted VMs.Script was modified to create rescue VM for troublehooting encrypted VM boot issues.This script works only on powershell which is available on Azure portal. 

# Overview
If an Azure VM is inaccessible it may be necessary to attach the OS disk to another Azure VM in order to perform recovery steps. The VM recovery scripts automate the recovery steps below.

1. Stops the problematic Encrypted VM.
2. Takes a snapshot of the problematic VM's OS disk and creates a copy of disk from snapshot.
3. Creates a new temporary VM ("rescue VM"). 
4. Attaches the copy of problematic's VM's OS disk as a data disk on the rescue VM.
5. You can then connect to the rescue VM to investigate and mitigate issues with the problem VM's OS disk.

# Supported VM Types

This version of the VM recovery script is for use with Azure VMs created using the Azure Resource Manager (ARM) deployment model. It supports only Linux VMs whose OS disk in encrypted and it should be Managed disk.

## When would you use the script?

The VM recovery script is most applicable when a VM is not booting, as seen on the VM screenshot in [boot diagnostics](https://azure.microsoft.com/blog/boot-diagnostics-for-virtual-machines-v2/) in the Azure portal.

## Usage
### Cloud Shell PowerShell
1. Launch PowerShell in Azure Cloud Shell 

   <a href="https://shell.azure.com/powershell" target="_blank"><img border="0" alt="Launch Cloud Shell" src="https://shell.azure.com/images/launchcloudshell@2x.png"></a>

2. If it is your first time connecting to Azure Cloud Shell, select **`PowerShell (Linux)`** when you see **`Welcome to Azure Cloud Shell`**. 

3. If you then see **`You have no storage mounted`**, select the subscription where the VM you are troubleshooting resides, then select **`Create storage`**.

4. From the **`PS Azure:/>`** prompt type **`cd /`** then **`<ENTER>`**.

5. Run the following command to download the scripts. Git is preinstalled in Cloud Shell. You do not need to install it separately.
   ```PowerShell
   git clone https://github.com/dibaskar/encryptedvm-support-scripts $home/encryptedvm-support-scripts
   ```
6. Switch into the folder by running:
   ```PowerShell
   cd $home/encryptedvm-support-scripts
   ```


7. If there are multiple subscriptions available then please selet your problematic VM's subscription using the below command:
   ```PowerShell
   Select-AzureSubscription -SubscriptionId 4xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx8a2
   ```


 

8. Run the following command to create a new "rescue VM" and attach the OS disk of the problem VM to the rescue VM as a data disk:
   ```PowerShell
   ./new-rescue.ps1
   vmName:   ( Problematic VM's Name )
   ResourceGroupName:  ( Problematic VM's Resource Group Name )
   Encryption_type:  ( This information can be gathered from ASC.Encryption using AAD Credentials is Dual and without AAD Credentials is single )
   rescueVMName:  ( Rescue VM's name )
   rescuevmusername:  ( Rescue VM's username )
   rescuevmpassword:  ( Rescue VM's Password. Password length should be minimum 12 characters with special characters in it else rescue VM creation will fail )
   ```

9. SSH to the rescue VM to mount the attached encrypted OS disk and proceed with further troubleshooting.

