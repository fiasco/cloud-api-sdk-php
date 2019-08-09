<?php

namespace AcquiaCloudApi;

use GuzzleHttp\Client;
use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\Key;
use GuzzleHttp\HandlerStack;
use cebe\openapi\Reader;
use cebe\openapi\ReferenceContext;

class AcquiaCloudApi {
  const OPENAPI_SPEC = 'https://cloudapi-docs.acquia.com/acquia-spec.yaml';

  protected $client;

  protected $specification;

  protected $operations = [];

  public function __construct(string $api_key, string $secret, ?HandlerStack $handler)
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

    $key = new Key($api_key, $secret);
    $middleware = new HmacAuthMiddleware($key);

    if (empty($handler)) {
      $handler = HandlerStack::create();
    }
    $handler->push($middleware);
    $this->client = new Client([
      'handler' => $handler,
      'base_uri' => $this->specification->servers[0]->url . '/',
    ]);
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

    $request_options = ['query' => $valid_parameters];

    if ($this->operations[$method]->method == 'POST' && !empty($arg[1])) {
      $request_options['json'] = $arg[1];
    }

    $response = $this->client->request(
      $this->operations[$method]->method,
      substr($path, 1),
      $request_options
    );

    // $schema = $this->operations[$method]
    //   ->responses[$response->getStatusCode()]
    //   ->content['application/json']
    //   ->schema;

    $body = $response->getBody();

    if ($response->getStatusCode() != 200) {
      $json = json_decode($body, TRUE);
      throw new ResponseException($response, strtr('error: message', $json['value']));
    }

    if ($json = json_decode($body, TRUE)) {
      return $json;
    }

    return $body;
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
