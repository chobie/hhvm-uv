<?hh
<<__Native>>
function uv_default_loop(): resource;

<<__Native>>
function uv_run(): int;

<<__Native>>
function uv_timer_init(?resource $loop = NULL): resource;

<<__Native>>
function uv_timer_start(resource $timer, int $timeout, int $repeat, mixed $callable) : void;

<<__Native>>
function uv_timer_stop(resource $timer) : void;

<<__Native>>
function uv_timer_again(resource $timer) : void;

<<__Native>>
function uv_timer_set_repeat(resource $timer, int $repeat) : void;

<<__Native>>
function uv_timer_get_repeat(resource $timer) : int;


<<__Native>>
function uv_http_parser_init(?int $target = 0) : resource;

<<__Native>>
function uv_http_parser_execute(resource $parser, string $body, ?array &$result) : mixed;

<<__Native>>
function uv_tcp_init(?resource $loop = NULL): resource;

<<__Native>>
function uv_tcp_nodelay(resource $tcp, bool $enabled): void;

<<__Native>>
function uv_accept(resource $server, resource $client): bool;

<<__Native>>
function uv_ip4_addr(string $address, int $port): resource;

<<__Native>>
function uv_tcp_bind(resource $server, resource $sockaddr): bool;

<<__Native>>
function uv_listen(resource $server, int $backlog, mixed $callable): void;

<<__Native>>
function uv_read_start(resource $handle, mixed $callable): void;
