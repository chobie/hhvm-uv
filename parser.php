<?hh

$parser = uv_http_parser_init();
$data = <<<EOF
GET / HTTP/1.0
Host: chobie.net


EOF;

$bval = uv_http_parser_execute($parser, $data, $result);
var_dump($bval);
var_dump($result);