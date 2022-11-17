# FileRedirector

This Project is for Windows File System Access Redirection.

So the Kernel Driver register for Pre Create Operation (**IRP_MJ_CREATE**) and Pre Network Query Open(**IRP_MJ_NETWORK_QUERY_OPEN**) with the Filter Manger, then when a User-Mode process try to access any file it send the **DOS File Name** to the User-Mode Client, then it will redirect