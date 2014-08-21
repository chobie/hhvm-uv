<?hh

//$tcp = uv_tcp_init();
//$address = uv_ip4_addr("0.0.0.0", 9999);
//uv_tcp_bind($tcp, $address);
//
//uv_listen($tcp, 511, function($server, $status) {
//    $client = uv_tcp_init();
//    uv_tcp_nodelay($client, 1);
//    uv_accept($server, $client);
//
//    uv_read_start($client, function($client, $nread, $buffer) {
//        if ($nread < 0) {
//            uv_close($client, function() {
//                echo "CLOSE";
//            });
//            return;
//        }
//
//        uv_write($client, $buffer, function() {
//
//        });
//        var_dump($buffer);
//    });
//});

createServer(function($result, HttpResponse $response) {

    $response->writeHead(200, array("Content-type:" =>  "text/plain"));
    $response->write("Hello");

})->listen(9999, "127.0.0.1", true);


function createServer(Closure $closure)
{
    $server = new HttpServer();
    $server->addEngine(new HttpEngineOnePointZero());
    $server->addEngine(new HttpEngineOnePointOne());
    $server->addListener($closure);

    return $server;
}

class HttpResponse
{
    protected $server;
    protected $client;

    protected $code = 200;

    protected $headers = array();

    protected $body = array();

    protected $http_version = "1.0";

    protected static $message = array(
        "101" => "Switching Protocols",
        "200" => "OK",
        "201" => "Created",
        "202" => "Accepted",
        "203" => "Non-Authoritative Information",
        "204" => "No Content",
        "205" => "Reset Content",
        "206" => "Partial Content",
        "207" => "Multi-Status",
        "226" => "IM Used",

        "300" => "Multiple Choices",
        "301" => "Moved Permanently",
        "302" => "Found",
        "303" => "See Other",
        "304" => "Not Modified",
        "305" => "Use Poxy",
        "306" => "",
        "307" => "Temporary Redirect",

        "400" => "Bad Request",
        "401" => "Unauthorized",
        "402" => "Payment Required",
        "403" => "Forbidden",
        "404" => "Not Found",
        "405" => "Method Not Allowed",
        "406" => "Not Acceptable",
        "407" => "Proxy Authentication Required",
        "408" => "Request Timeout",
        "409" => "Conflict",
        "410" => "Gone",
        "411" => "Length Required",
        "412" => "Precondition Failed",
        "413" => "Request Entity Too Large",
        "414" => "Request-URI Too Long",
        "415" => "Unsupported Media Type",
        "416" => "Requested Range Not Satisfiable",
        "417" => "Expectation Failed",
        "418" => "I'm a teapot",
        "422" => "Unprocessable Entity",
        "423" => "Locked",
        "424" => "Failed Dependency",
        "426" => "Upgrade Required",

        "500" => "Internal Server Error",
        "501" => "Not Implemented",
        "502" => "Bad Gateway",
        "503" => "Service Unavailable",
        "504" => "Gateway Timeout",
        "505" => "HTTP Version Not Supported",
        "506" => "Variant Also Negotiates",
        "507" => "Insufficient Storage",
        "509" => "Bandwidth Limit Exceeded",
        "510" => "Not Extended",
    );

    public function __construct($server, $client)
    {
        $this->client = $client;
        $this->server = $server;
    }

    public function writeHead($code, array $headers)
    {
        $this->code = $code;
        $this->headers = $headers;
    }

    public function write($data)
    {
        $this->body[] = $data;
    }

    public function flush()
    {
        $buffer = sprintf("HTTP/1.1 %d %s\r\n", $this->code, self::$message[$this->code]);
        foreach ($this->headers as $key => $value) {
            $buffer .= $key . ": " . $value . "\r\n";
        }

        $buffer .= "\r\n";
        if ($this->body) {
            $buffer .= join("", $this->body);
        }

        uv_write($this->client, $buffer);
    }

    public function end()
    {
        $buffer = sprintf("HTTP/1.1 %d %s\r\n", $this->code, self::$message[$this->code]);
        foreach ($this->headers as $key => $value) {
            $buffer .= $key . ": " . $value . "\r\n";
        }
        $buffer .= "\r\n";
        if ($this->body) {
            $buffer .= join("", $this->body);
        }

        uv_write($this->client, $buffer, array($this->server, "onWrite"));
    }
}

class Client
{
    protected $websocket = false;

    protected $socket;

    protected $parser;

    protected $created_at;

    protected $endponint;

    protected $should_close = false;

    public function __construct($socket)
    {
        $this->socket = $socket;
        $this->parser = uv_http_parser_init();
        $this->created_at = time();
    }

    public function setEndPoint($endpoint)
    {
        $this->endpoint = $endpoint;
    }

    public function getEndpoint()
    {
        return $this->endpoint;
    }

    public function __destruct()
    {
        unset($this->websocket);
        unset($this->socket);
        unset($this->parser);
        unset($this->created_at);
        unset($this->should_close);
    }

    public function getSocket()
    {
        return $this->socket;
    }

    public function getParser()
    {
        return $this->parser;
    }

    public function isWebSocket()
    {
        return $this->websocket;
    }

    public function setWebsocket($booleaan)
    {
        $this->websocket = $booleaan;
    }

    public function shouldClose($boolean = null)
    {
        if (is_null($boolean)) {
            return $this->should_close;
        } else {
            $this->should_close = $boolean;
        }
    }
}

class HttpEngineOnePointOne
{
    public function getVersion()
    {
        return "1.1";
    }

    public function __construct()
    {
    }

    public function execute($result, Client $client, HTTPResponse $response, $closure)
    {
        if ($result['UPGRADE']) {
            $key = $result['HEADERS']['SEC_WEBSOCKET_KEY'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
            $raw_key = sha1($key, true);

            $response->writeHead(101, array(
                "Upgrade"              => "websocket",
                "Connection"           => "Upgrade",
                "Sec-WebSocket-Accept" => base64_encode($raw_key),
            ));
            $response->flush();
            $client->setWebsocket(true);
            $client->setEndPoint($result["QUERY_STRING"]);
            World::getInstance()->addClient($client);
            return;
        } else {
            $closure($result, $response);
        }

        if ( isset($result['HEADERS']['CONNECTION']) &&
                $result['HEADERS']['CONNECTION'] === "close") {
            $client->shouldClose(true);
        }
    }
}

class HttpEngineOnePointZero
{
    public function getVersion()
    {
        return "1.0";
    }

    public function __construct()
    {
    }

    public function execute($result, Client $client, HTTPResponse $response, $closure)
    {
        $closure($result, $response);
        $client->shouldClose(true);
    }
}

class HttpServer
{
    /** @var  resource $server */
    protected $server;

    protected $clients = array();

    /** @var  Closure $closure */
    protected $closure;

    public function __construct()
    {
        $this->server = uv_tcp_init();
    }

    public function addEngine($engine)
    {
        $this->engines[$engine->getVersion()] = $engine;
    }

    public function getEngine($version)
    {
        if (isset($this->engines[$version])) {
            return $this->engines[$version];
        }

        throw new InvalidArgumentException("not supported version");
    }

    public function addListener($closure)
    {
        $this->closure = $closure;
    }

    public function onShutdown($handle, $status)
    {
        //echo "onShutdown\n";
        uv_close($handle, array($this, "onClose"));
    }

    public function onClose($handle)
    {
        //echo "onClose\n";
        $this->clients[(int)$handle]->shouldClose(true);
        unset($this->clients[(int)$handle]);
    }

    public function onWrite($client, $status)
    {
        if ($status == 0) {
            //echo "[write_successed]\n";
            //uv_shutdown($client, array($this, "onShutdown"));
        } else {
            //echo "[write_failed]";
        }
    }

    public function onRead($socket, $nread, $buffer)
    {
        $client = $this->clients[(int)$socket];

        if ($nread < 0) {
            uv_close($socket, array($this, "onClose"));
        } else if ($nread == 0) {
            // nothing to do.
        } else {
            $result = array();

            if ($client->isWebSocket()) {
                $result = WebSocketFrame::parseFromString($buffer);

                // put closure here.

                $frame = new WebSocketFrame();
                $frame->setPayload($result->getPayload());
                uv_write($socket, $frame->serializeToString());
                return;
            } else if (uv_http_parser_execute($client->getParser(), $buffer, $result)) {
                $response = new HttpResponse($this, $socket);

                try {
                    $engine = $this->getEngine($result['HEADERS']['VERSION']);
                    $engine->execute($result, $client, $response, $this->closure);
                    $response->end();

                    if ($client->shouldClose()) {
                        //echo "shouldClose\n";
                        uv_shutdown($socket, array($this, "onShutdown"));
                        return;
                    } else {
                        uv_close($socket, array($this, "onClose"));
                    }
                } catch (Exception $e) {
                    echo $e->getMessage();
                    $response->writeHead(500, array());
                    $response->write("Internal Server Error");
                    $response->end();
                }
                unset($response);
            }
        }
    }

    public function onConnect($server, $status)
    {
        $client = uv_tcp_init();
        uv_tcp_nodelay($client, 1);
        uv_accept($server, $client);
        $this->clients[(int)$client]   = new Client($client);

        uv_read_start($client, array($this, "onRead"));
    }

    public function listen($port, $address = "127.0.0.1", $run = true)
    {
        uv_tcp_nodelay($this->server, 1);

        uv_tcp_bind($this->server, uv_ip4_addr($address, $port));
        uv_listen($this->server, 511, array($this, "onConnect"));

        if ($run) {
            uv_run();
        }
    }
}
