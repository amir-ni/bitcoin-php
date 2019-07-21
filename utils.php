<?php

$config = [
    'nodeIp' => '46.19.137.74',
    'isTestNet' => false,
    'localIp' => '127.0.0.1',
    'localPort' => 8008,
    'microSleep' => 10000,
];

$version    = 70015;
$coreVersion = 'v0.13.2';
$nodePort   = $config['isTestNet'] ? 18333 : 8333;
$magicBytes = $config['isTestNet'] ? '0B 11 09 07' : 'F9 BE B4 D9';
$ipv6_prefix = '00 00 00 00 00 00 00 00 00 00 FF FF';

$serviceIdentifiers = [
    'Unnamed' => '00 00 00 00 00 00 00 00',
    'NODE_NETWORK' => '01 00 00 00 00 00 00 00',
    'NODE_GETUTXO' => '02 00 00 00 00 00 00 00',
    'NODE_BLOOM' => '04 00 00 00 00 00 00 00',
    'NODE_WITNESS' => '08 00 00 00 00 00 00 00',
    'NODE_XTHIN' => '10 00 00 00 00 00 00 00',  
];

// convert endian types
function swapEndian($data) {
    return implode('', array_reverse(str_split($data, 2)));
}

// convert hex to ascii string
function hex2str($hex) {
    $str = '';
    for($i=0;$i<strlen($hex);$i+=2) $str .= chr(hexdec(substr($hex,$i,2)));
    return trim($str);
}

function parseHexNumber($hex){
    $res = [];
    for($i=0;$i<strlen($hex);$i+=2) $res[] = hexdec(substr($hex,$i,2));
    return $res;

}


function parseIp($hexIp){
    global $ipv6_prefix;
    $ipV4 = boolval( str_replace(' ', '',$ipv6_prefix) == strtoupper(substr($hexIp, 0, 24)) );

    if($ipV4){
        $hex = substr($hexIp, -8);
        return implode(parseHexNumber($hex), '.');
    }else{
        return $hexIp;
    }

}

// convert ascii string to hex
function str2hex($ascii) {
    $hex = '';
    for ($i = 0; $i < strlen($ascii); $i++) {
        $byte = strtoupper(dechex(ord($ascii{$i})));
        $byte = str_repeat('0', 2 - strlen($byte)).$byte;
        $hex .= $byte;
    }
    return $hex;
}

// add zeros to the left side of the string till extend to the intended size
function fieldSize($field, $bytes = 1) {
    return str_pad($field, $bytes * 2, '0', STR_PAD_LEFT);
}

// add spaces between bytes
function byteSpaces($bytes) { 
    $bytes = implode(str_split(strtoupper($bytes), 2), ' ');
    return $bytes;
}

// gets and print socket errors
function socketError() {
    $error = socket_strerror(socket_last_error());
    echo $error.PHP_EOL.PHP_EOL;
}

// convert timestamp to network byte order
function timestamp($time) { 
    $time = dechex($time);
    $time = fieldSize($time, 8);
    $time = swapEndian($time);
    return byteSpaces($time);
}

// convert ip address to network byte order
function networkAddress($ip, $port = '8333') { 
    global $serviceIdentifiers, $ipv6_prefix;
    $services = $serviceIdentifiers['NODE_NETWORK'];

    $ip = explode('.', $ip);
    $ip = array_map("dechex", $ip);
    $ip = array_map("fieldSize", $ip);
    $ip = array_map("strtoupper", $ip);
    $ip = implode($ip, ' ');

    $port = dechex($port); // should be big-endian
    $port = byteSpaces($port);

    return "$services $ipv6_prefix $ip $port";
}

// create checksum of message payloads for message headers
function checksum($string) { 
    $string = hex2bin($string);
    $hash = hash('sha256', hash('sha256', $string, true));
    $checksum = substr($hash, 0, 8);
    return byteSpaces($checksum);
}

function parseVarInt($varInt){
    switch(substr($varInt, 0, 2)){
        case 'ff':
            return hexdec(swapEndian(substr($varInt, 2, 16)));
        case 'fe':
            return hexdec(swapEndian(substr($varInt, 2, 8)));
        case 'fd':
            return hexdec(swapEndian(substr($varInt, 2, 4)));
        default:
            return hexdec(substr($varInt, 0, 2));
    }
}

function varIntSize($varInt){
    switch(substr($varInt, 0, 2)){
        case 'ff':
            return 16;
        case 'fe':
            return 8;
        case 'fd':
            return 4;
        default:
            return 2;
    }
}

function sendMessage($socket, $command, $payload) {

    echo "sending $command...".PHP_EOL;
    
    global $magicBytes;
    $command = str_pad(str2hex($command), 24, '0', STR_PAD_RIGHT);
    $payloadSize = byteSpaces(swapEndian(fieldSize(dechex(strlen($payload) / 2), 4)));
    $checksum = checksum($payload);

    $header_array = [
        'magicbytes'    => $magicBytes,
        'command'       => $command,
        'payload_size'  => $payloadSize,
        'checksum'      => $checksum,
    ];

    $header = str_replace(' ', '', implode($header_array));
	
    $msg = $header.$payload;

    socket_send($socket, hex2bin($msg), strlen($msg) / 2, 0);

}
