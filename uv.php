<?hh
<<__Native>>
function uv_default_loop(): resource;

<<__Native>>
function uv_run(): int;

<<__Native>>
function uv_timer_init(?resource $loop): resource;

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