<?php

namespace AcquiaCloudApi;

use AcquiaCloudApi\Connector\Client;
use AcquiaCloudApi\Connector\Connector;
use cebe\openapi\Reader;
use cebe\openapi\ReferenceContext;

class AcquiaCloudApi {
  const OPENAPI_SPEC = 'https://cloudapi-docs.acquia.com/acquia-spec.yaml';

  protected $client;

  protected $specification;

  protected $operations = [];

  public function __construct(string $api_key, string $secret)
  {

    $this->specification = Reader::readFromYaml(__DIR__ . '../' . file_get_contents(__DIR__ . '/../acquia-spec.yaml'));
    $this->specification->setReferenceContext(new ReferenceContext($this->specification, self::OPENAPI_SPEC));
    $this->specification->resolveReferences();

    // Build an index of operations that can be called by operationId.
    foreach ($this->specification->paths as $path => $api) {
      if (isset($api->get)) {
        $api->get->path = $path;
        $api->get->method = 'GET';
        $this->operations[$api->get->operationId] = $api->get;
      }
      if (isset($api->post)) {
        $api->post->path = $path;
        $api->post->method = 'POST';
        $this->operations[$api->post->operationId] = $api->post;
      }
      if (isset($api->delete)) {
        $api->delete->path = $path;
        $api->delete->method = 'DELETE';
        $this->operations[$api->delete->operationId] = $api->delete;
      }
    }

    $config = [
        'key' => $api_key,
        'secret' => $secret,
    ];

    $connector = new Connector($config);
    $this->client = Client::factory($connector);
  }

  public function withClient(Client $client)
  {
    return $this;
  }

  public function __call($method, $args)
  {
    if (!isset($this->operations[$method])) {
      throw new \BadMethodCallException("$method does not exist.");
    }
    // Validate the parameters are present.
    $parameters = empty($args) ? [] : $args[0];
    $valid_parameters = [];
    $parameter_names = [];
    foreach ($this->operations[$method]->parameters as $parameter) {
      if ($parameter->required && !isset($parameters[$parameter->name])) {
        throw new \BadMethodCallException("$method is missing a required parameter: {$parameter->name}.");
      }
      $parameter_names[] = $parameter->name;
    }

    foreach ($parameter_names as $name) {
      if (isset($parameters[$name])) {
        $valid_parameters[$name] = $parameters[$name];
        unset($parameters[$name]);
      }
    }

    if (count($parameters)) {
      throw new \InvalidArgumentException("Invalid parameters passed into $method: " . implode(', ', array_keys($parameters)));
    }

    $path = $this->operations[$method]->path;
    foreach ($valid_parameters as $name => $value) {
      $token = '{' . $name . '}';
      if (strpos($path, $token) !== FALSE) {
        $path = str_replace($token, $value, $path);
        // Remote parameters that won't be sent via HTTP query.
        unset($valid_parameters[$name]);
      }
    }

    $request_options = [];
    // Add query parameters to $this->query
    if (!empty($valid_parameters)) {
      foreach ($valid_parameters as $name => $value) {
        $this->client->addQuery($name, $value);
      }
    }

    if ($this->operations[$method]->method == 'POST' && !empty($arg[1])) {
      $request_options['json'] = $arg[1];
    }

    $this->client->clearOptions();
    return $this->client->request(
      $this->operations[$method]->method,
      $path,
      $request_options
    );
  }

  public function getCommands()
  {
    return array_keys($this->operations);
  }

  public function getClient()
  {
    return $this->client;
  }
}

 ?>
