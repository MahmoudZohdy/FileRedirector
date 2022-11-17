# FileRedirector

This Project is for Windows File System Access Redirection.

The Kernel Driver register for Pre Create Operation (**IRP_MJ_CREATE**) and Pre Network Query Open (**IRP_MJ_NETWORK_QUERY_OPEN**) with the Filter Manger, then when a User-Mode process try to access any file it send the **DOS File Name** and the **Process ID** of the requestor process to the User-Mode Client, then the User-Mode Client will check if the File Path needs to be redirected and if the process that is accessing it is authorized for this access and if not authorized it will redirect it to another path of your choose (Need to be a DOS file path).


In our case the User-Mode Client (**UserClient.exe**) checks if any access to the file **File1.txt** in the same directory as **UserClient.exe** it will redirect it to the file **File2.txt**.


for example, if **UserClient.exe** is in **C:\Redirector\UserClient.exe** and you try to access **C:\Redirector\File1.txt** it will be redirected to the file **C:\Redirector\File2.txt**

![](https://github.com/MahmoudZohdy/FileRedirector/blob/main/images/FileRedirector.PNG)

You can do the mapping as you like as long as the New Path is in the DOS format.


Kindly note that this is only for educational purposes only

# Reference

https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter/simrep


# License:
MIT