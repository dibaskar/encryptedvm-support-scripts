<<<<<<< HEAD
# Please note : This powershell script was created from https://github.com/Azure/azure-support-scripts/tree/master/VMRecovery/ResourceManager which was written by Windows PG for rescue VM creation for non encrypted VMs.Script was modified to create rescue VM for troubleshooting encrypted VM boot issues.This script works only on powershell which is available on Azure portal. 

# Overview
If an Azure VM is inaccessible it may be necessary to attach the OS disk to another Azure VM in order to perform recovery steps. The VM recovery scripts automate the recovery steps below.

1. Stops the problematic Encrypted VM.
2. Takes a snapshot of the problematic VM's OS disk and creates a copy of disk from snapshot.
3. Creates a new temporary VM ("rescue VM"). 
4. Attaches the copy of problematic VM's OS disk as data disk on the rescue VM.
5. You can then connect to the rescue VM to investigate and mitigate issues with the problematic VM's OS disk.

# Supported VM Types

This version of the VM recovery script is for use with Azure VMs created using the Azure Resource Manager (ARM) deployment model. It supports only Linux VMs whose OS disk is encrypted and it should be Managed disk.
## Usage
### Cloud Shell PowerShell
1. Launch PowerShell in Azure Cloud Shell 

   <a href="https://shell.azure.com/powershell" target="_blank"><img border="0" alt="Launch Cloud Shell" src="https://shell.azure.com/images/launchcloudshell@2x.png"></a>

2. If it is your first time connecting to Azure Cloud Shell, select **`PowerShell`** when you see **`Welcome to Azure Cloud Shell`**. 

3. If you then see **`You have no storage mounted`**, select the subscription where the VM you are troubleshooting resides, then select **`Create storage`**.

4. From the **`PS Azure:/>`** prompt type **`cd /`** then **`<ENTER>`**.

5. Run the following command to download the scripts. Git is preinstalled in Cloud Shell. You need not to install it seperately.
   ```PowerShell
   git clone https://github.com/dibaskar/encryptedvm-support-scripts $home/encryptedvm-support-scripts
   ```
6. Switch into the folder by running:
   ```PowerShell
   cd $home/encryptedvm-support-scripts
   ```


7. Please execute the below commands to set the impacted VM's subscription details.**`Please note : Both these commands need to be executed in powershell to set the subcriptions as the script consists of both bash and powershell commands.`**
   ```PowerShell
   Set-AzureRmContext -SubscriptionId 4xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx8a2
   az account set --subscription 4xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx8a2
   ```

8. Execute the script as mentioned below create a new "rescue VM" and attach the OS disk of the problem VM to the rescue VM as data disk:
   ```PowerShell
   ./new-rescue.ps1
   vmName:   ( Problematic VM's Name )
   ResourceGroupName:  ( Problematic VM's Resource Group Name )
   Encryption_type:  ( This information can be gathered from ASC.Encryption using AAD Credentials is Dual and without AAD Credentials is single )
   rescueVMName:  ( Rescue VM's name )
   rescuevm_require_public_ip : ( Does rescue VM requires public IP. <b> Valid options are yes or no </b> )
   rescuevmusername:  ( Rescue VM's username )
   rescuevmpassword:  ( Rescue VM's Password. Password length should be minimum 12 characters with special characters in it else rescue VM creation will fail )
   ```

   **`Please note : If VM is created from specialised disk then you will be prompted to enter image name manually as below`**.
   ```PowerShell
   ./new-rescue.ps1
   ################ ######### VM seems to be created from specialised Disk.
   Enter image name. ( Valid Image names are RHEL,SLES,UBUNTU,CENTOS ):
   ```

   **`a) If Encryption is single then ADE extension will be installed on rescue VM for making BEK volume available`**.
   ```PowerShell
     Enable AzureDiskEncryption on the VM
     This cmdlet prepares the VM and enables encryption which may reboot the machine and takes 10-15 minutes to finish. Please save your      work on the VM before confirming. Do you want to continue?
     [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): ( Please enter Y here )
     ```
   

9. Commands for mounting the disk on rescue VM will be printed once script execution is done. SSH to the rescue VM for mounting the attached encrypted OS disk and proceed with further troubleshooting **`Please note : There will be slight change in these mount commands based on the OS distro`**.

