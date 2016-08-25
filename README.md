## foreman scripts
*Python scripts to get host details from foreman, using forman api

## usage
you can add your credentials in ~./foremanrc to avoid repeately entering username/password, if you wish

format is
````
user.name=<your_username>
user.password=<your_password>
````

or set following two env variable.

````
export foreman_user=username
export foreman_pw=password
````

SETUP:
# set your forman api url env variable

````
export foreman_apibaseurl=https://foreman_url/api
````
or in forman_common.py set var default_endpoint to your correct endpoint

````
default_endpoint="https://<your_foreman_api_url>/api"
````
