<?php

$begin = microtime(1);
for ($i = 0; $i < 19086; $i++) {
$result = array();
$parser = uv_http_parser_init();
$data = <<<EOF
GET /hello.php?id=1#world HTTP/1.1
Host: chobie.net
Connection: close
X-HTTP-Hoge: hoge

EOF;

$bval = uv_http_parser_execute($parser, $data, $result);
//var_dump($bval);
//var_dump($result);
unset($parser);
}
$end = microtime(1);
var_dump($end - $begin);