# Simple Azure Authentication for Python web application

### Overview

This sample demonstrates a Python web application that signs-in users with the Microsoft identity platform.

1. Authentication is performed via **identity token**
1. Role-based access is implemented via **App roles**

Since we are using [OpenID Connect](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc) there is no need to provision any credentials (secret key or certificate) for Azure application.

If you are interested in implementing [Authorization Code Flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow) refer to official [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python) library and [this](https://github.com/Azure-Samples/ms-identity-python-webapp) sample. Keep in mind however that authorization code flow requires you to provision credentials for your Azure application. 
 
## How to run this sample

To run this sample, you'll need:

> - [Python 3+](https://www.python.org/downloads/release/python-364/)
> - An Azure Active Directory (Azure AD) tenant. For more information on how to get an Azure AD tenant, see [how to get an Azure AD tenant.](https://docs.microsoft.com/azure/active-directory/develop/quickstart-create-new-tenant)


### Step 1:  Clone or download this repository

From your shell or command line:

```Shell
git clone https://github.com/alexagr/simple-azure-auth.git
```

or download and extract the repository .zip file.

### Step 2:  Register the sample application with your Azure Active Directory tenant

#### Choose the Azure AD tenant where you want to create your applications

As a first step you'll need to:

1. Sign in to the [Azure portal](https://portal.azure.com).
1. If your account is present in more than one Azure AD tenant, click **Directory + subscription** filter and select the tenant in which you want to register an application.

#### Register the Python Webapp (python-webapp)

1. Navigate to the [App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) page.
1. Select **New registration**.
1. On the **Register an application page** enter your application's registration information:
   - In the **Name** section, enter a meaningful application name that will be displayed to users of the app, for example `python-webapp`.
   - In the **Supported account types** section choose **Accounts in this organizational directory only (AudioCodes Ltd only - Single tenant)**.
   - In the **Redirect URI (optional)** section, select **Web** in the combo-box and enter the following redirect URIs: `http://localhost:5000/authToken`.
1. Select **Register** to create the application.
1. On the app **Overview** page, find the **Application (client) ID** and **Directory (tenant) ID** values and record them for later.
1. On the app **Authentication** page, in the **Implicit grant and hybrid flows** enable **ID tokens (used for implicit and hybrid flows)** and click **Save**.
1. (Optional) If you want to enable role-based access to the application:
   - On the **App roles** page click **Create app role**.
   - For **Display name** enter `Administrator`.
   - For **Allowed member types** select **Users/Groups**.
   - For **Value** enter `Administrator`.
   - For **Description** enter `Sample python-webapp administrator`.
   - Click **Apply**. 
   - Navigate to the [Enterprise applications](https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade) page.
   - In the search string enter name of the application registered in the previous steps: `python-webapp`.
   - Click on the application name.
   - On the **Users and groups** page click **Add user/group**
     - For **Users and groups** select user of group who is allowed to access the application.
     - For **Select a role** select **Administrator** role
     - Click **Assign**.   

### Step 3:  Configure the sample to use your Azure AD tenant

1. Open the `app_config.py` file
1. Find the app key `Enter_the_Application_Id_here` and replace the existing value with the **Application (client) ID** of the `python-webapp` application copied from the Azure portal.
1. Find the app key `Enter_the_Tenant_ID_Here` and and replace the existing value with the **Directory (tenant) ID** of the `python-webapp` application copied from the Azure portal.
1. (Optional) If you want to enable role-based access to the application:
   - Change USER_ROLE to `"Administrator"`

### Step 4: Run the sample

- You will need to install dependencies using pip as follows:
```Shell
$ pip install -r requirements.txt
```

Run app.py from shell or command line. Note that the host and port values need to match what you've set up in your redirect_uri:

```Shell
$ flask run --host localhost --port 5000
```

## More information

For more information about how OAuth 2.0 protocols work in this scenario and other scenarios, see [OAuth 2.0 and OpenID Connect protocols on the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols).
