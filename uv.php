<?hh
<<__Native>>
function uv_default_loop(): resource;

<<__Native>>
function uv_run(): int;

<<__Native>>
function uv_timer_init(?resource $loop): resource;

<<__Native>>
function uv_timer_start(resource $timer, int $timeout, int $repeat, mixed $callable) : void;
