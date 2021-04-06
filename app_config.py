TENANT_ID = "Enter_the_Tenant_Id_here" # Directory (tenant) ID of app registration

CLIENT_ID = "Enter_the_Application_Id_here" # Application (client) ID of app registration

MULTI_TENANT = False # Allow login from accounts in any organizational directory

REDIRECT_PATH = "/authToken"  # Used for forming an absolute URL to your redirect URI.
                              # The absolute URL must match the redirect URI you set
                              # in the app's registration in the Azure portal.

USER_ROLE = None # If configured only users who are assigned with this role are allowed to login
