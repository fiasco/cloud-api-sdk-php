<?php

namespace AcquiaCloudApi;

use Psr\Http\Message\ResponseInterface;

class ResponseException extends \Exception {
  protected $response;

  public function __construct(ResponseInterface $response, $message, $code = 1)
  {
    $this->response = $response;
    parent::__construct($message, $code);
  }

  public function getResponse()
  {
    return $response;
  }
}

 ?>
