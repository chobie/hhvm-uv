<?hh

$timer = uv_timer_init(NULL);
uv_timer_start($timer, 0, 1000, function($timer){
    var_dump(uv_timer_get_repeat($timer));
    echo 1 . PHP_EOL;
});
uv_run();
