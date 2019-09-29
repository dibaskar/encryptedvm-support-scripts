<<<<<<< HEAD
# Overview
# Please note : This powershell script was created from https://github.com/Azure/azure-support-scripts/tree/master/VMRecovery/ResourceManager which was written by Windows PG for rescue VM creation for non encrypted VMs.Script was modified to create rescue VM for trouble encrypted VM boot issues. 
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
7. Run the following command to create a new "rescue VM" and attach the OS disk of the problem VM to the rescue VM as a data disk:
   ```PowerShell
   ./New-AzureRMRescueVM.ps1 -ResourceGroupName <resourceGroupName> -VmName <vmName>
   ```
   If you need to verify the resource group name and VM name, run **`Get-AzureRmVM`**. If you need to verify the subscription ID, run **`Get-AzureRmSubscription`**.
   
   If the problem VM is a Windows VM, the rescue VM is created from the Windows Server 2016 marketplace image that has the Desktop Experience installed. 
   
   If the problem VM is a Linux VM, the rescue VM is created from the Ubuntu 16.04 LTS marketplace image. 
   
   You can use the -publisher/-offer/-sku parameters when running New-AzureRMRescueVM.ps1 if you need to create the rescue VM from a different marketplace image.

8. When New-AzureRMRescueVM.ps1 completes, it will create a PowerShell script, `Restore_<problemVmName>.ps1`, that you will run later to swap the problem VM's OS disk back to the problem VM.

9. RDP to the rescue VM to resolve the issue with the OS disk of the problem VM.

10. To swap the problem VM's OS disk back to the problem VM, run the Restore_<problemVmName>.ps1 script located in the same folder as the recovery scripts.

### Local PowerShell
1. To download the recovery scripts you can download the zip file or use the Git client. 

   Download and extract zip file:

   https://github.com/Azure/azure-support-scripts/archive/master.zip

   Or download using Git client:

   You can use any local directory, c:\azure-support-scripts is just an example.

   ```PowerShell
   git clone https://github.com/Azure/azure-support-scripts $home\CloudDrive\azure-support-scripts 
   ```
2. Launch PowerShell locally.

3. The recovery scripts require the AzureRM PowerShell module. If you do not have it installed, you can install it by running the following command:

   ```PowerShell
   Install-Module -Name AzureRM
   ```
4. Login to your Azure subscription using the following command:
   ```PowerShell
   Connect-AzureRMAccount
   ```
If you receive an error that the Connect-AzureRMAccount cmdlet is not found, make sure you update to the latest AzureRM module version by running the following command:
   ```PowerShell
   Update-Module -Name AzureRM
   ```
5. Switch into the folder where you extracted the scripts, and then into the \VMRecovery\ResourceManager folder under that.

   For example, if you extracted the scripts to c:\azure-support-scripts, run the following command:
   ```PowerShell
   cd C:\azure-support-scripts\VMRecovery\ResourceManager
   ```
6. Run the following command to create a new "rescue VM" and attach the OS disk of the problem VM to the rescue VM as a data disk:
   ```PowerShell
   .\New-AzureRMRescueVM.ps1 -ResourceGroupName <resourceGroupName> -VmName <vmName>
   ```
   If you need to verify the resource group name and VM name, run **`Get-AzureRmVM`**. If you need to verify the subscription ID, run **`Get-AzureRmSubscription`**.

7. When New-AzureRMRescueVM.ps1 completes, it will create a PowerShell script, Restore_<problemVmName>.ps1, that you will run later to swap the problem VM's OS disk back to the problem VM.

8. RDP to the rescue VM to resolve the issue with the OS disk of the problem VM.

9. To swap the problem VM's OS disk back to the problem VM, run the Restore_<problemVmName>.ps1 script located in the same folder as the recovery scripts.

## Script help syntax

```PowerShell
get-help .\New-AzureRMRescueVM.ps1

get-help .\Restore-AzureRMOriginalVM.ps1
```
=======
# encryptedvm-support-scripts
Overview
If an Azure VM is inaccessible it may be necessary to attach the OS disk to another Azure VM in order to perform recovery steps. The VM recovery scripts automate the recovery steps below.
Stops the problem VM.
Takes a snapshot of the problem VM's OS disk.
Creates a new temporary VM ("rescue VM").
Attaches the problem VM's OS disk as a data disk on the rescue VM.
You can then connect to the rescue VM to investigate and mitigate issues with the problem VM's OS disk.
Detaches the problem VM's OS disk from the rescue VM.
Performs a disk swap to swap the problem VM's OS disk from the rescue VM back to the problem VM.
Removes the resources that were created for the rescue VM.

When would you use the script?
The VM recovery script is most applicable when a VM is not booting, as seen on the VM screenshot in boot diagnostics in the Azure portal.

Usage
Cloud Shell PowerShell
Launch PowerShell in Azure Cloud Shell
>>>>>>> cdabf1dc2cc50d7fa8f4074b90c09cbe27b40f0d
