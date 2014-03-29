<?hh

$tcp = uv_tcp_init();
$address = uv_ip4_addr("0.0.0.0", 9999);
uv_tcp_bind($tcp, $address);

uv_listen($tcp, 511, function($server, $status) {
    $client = uv_tcp_init();
    uv_tcp_nodelay($client, 1);
    uv_accept($server, $client);

    uv_read_start($client, function($client, $nread, $buffer) {
        var_dump($buffer);
    });
});
uv_run();
