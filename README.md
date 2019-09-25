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
