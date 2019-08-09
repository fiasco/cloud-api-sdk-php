# Acquia Cloud API PHP SDK

This is an unofficial PHP SDK for the Acquia Cloud API. It is built from the
Open API spec found at https://cloudapi-docs.acquia.com/acquia-spec.yaml.

# Installation

Use composer to install the library

```
composer require fiasco/cloud-api-sdk-php
```

# Usage

Create a client to connect to the API. You'll need an API key and secret. Follow
the documentation found here: https://docs.acquia.com/acquia-cloud/develop/api/auth/

```php

use AcquiaCloudApi\AcquiaCloudApi;

$api = new AcquiaCloudApi($key, $secret);
```
