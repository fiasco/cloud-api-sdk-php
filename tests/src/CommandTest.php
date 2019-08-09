<?php

namespace AcquiaCloudApiTests;

use PHPUnit\Framework\TestCase;
use AcquiaCloudApi\AcquiaCloudApi;

class CommandTest extends TestCase {

  public function testProfileRun()
  {
    $api = new AcquiaCloudApi();
    $apps = $api->getApplications();
    $this->assertIsIterable($apps);
  }
}

 ?>
