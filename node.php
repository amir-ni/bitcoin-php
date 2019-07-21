<?php
include 'utils.php';

// Connect to socket
echo "Connecting to {$config['nodeIp']}...".PHP_EOL;
$socket = socket_create(AF_INET, SOCK_STREAM, 6); 
socketError(); 
socket_connect($socket, $config['nodeIp'], $nodePort);

// Sending version message
$version_array = [ 
    'version'       => byteSpaces(swapEndian(fieldSize(dechex($version), 4))),        
    'services'      => $serviceIdentifiers['NODE_NETWORK'],       
    'timestamp'     => timestamp(time()),      
    'addr_recv'     => networkAddress($config['nodeIp'], $nodePort),           
    'addr_from'     => networkAddress($config['localIp'], $config['localPort']),           
    'nonce'         => byteSpaces(swapEndian(fieldSize(dechex(1), 8))),          
    'user_agent'    => '00',     
    'start_height'  => byteSpaces(swapEndian(fieldSize(dechex(0), 4))),    
];
$payload = str_replace(' ', '', implode($version_array));
sendMessage($socket, 'version', $payload);

// Keep receiving data
while (true) {

    while (socket_recv($socket, $byte, 24, MSG_WAITALL)) {

        $buffer = bin2hex($byte);

        if (strlen($buffer) == 48) {

            $magic = substr($buffer, 0, 8);
            $command  = hex2str(substr($buffer, 8, 24));
            $size = hexdec(swapEndian(substr($buffer, 32, 8)));
            $checksum = substr($buffer, 40, 8);
			
            socket_recv($socket, $payload, $size, MSG_WAITALL);
            $payload = bin2hex($payload);

            echo "received $command...".PHP_EOL;

			switch ($command) { 
                case 'version':
                    $receivedVersion = [
                        'version' => hexdec(swapEndian(substr($payload, 0, 8))),
                        'services' => byteSpaces(substr($payload, 8, 16)),
                        'timestamp' => hexdec(swapEndian(substr($payload, 24, 16))),
                        'addr_recv services' => byteSpaces(substr($payload, 40, 16)),
                        'addr_recv IP address' => parseIp(substr($payload, 56, 32)),
                        'addr_recv port' => hexdec(substr($payload, 88, 4)),
                        'addr_trans services' => byteSpaces(substr($payload, 92, 16)),
                        'addr_trans IP address' => parseIp(substr($payload, 108, 32)),
                        'addr_trans port' => hexdec(substr($payload, 140, 4)),
                        'nonce' => substr($payload, 144, 8),
                    ];
                    print_r($receivedVersion);
					sendMessage($socket,'verack', '');
					break;
                case 'inv':
                    $count = parseVarInt($payload);
                    for($i=0;$i<$count;$i++){
                        $input = (substr($payload,-72 * ($i+1),72));
                        switch(hexdec(swapEndian(substr($input,0, 8)))){
                            case '1':
                                echo 'MSG_TX: '.(substr($input, 8)).PHP_EOL;
                                break;
                            case '2':
                                echo 'MSG_BLOCK: '.(substr($input, 8)).PHP_EOL;
                                break;
                            case '3':
                                echo 'MSG_FILTERED_BLOCK: '.(substr($input, 8)).PHP_EOL;
                                break;
                            case '4':
                                echo 'MSG_CMPCT_BLOCK: '.(substr($input, 8)).PHP_EOL;
                                break;
                        }
                    }
					sendMessage($socket,'getdata', $payload);	
					break;
                case 'getblocks':
                    $hashCount = parseVarInt(substr($payload, 8));
                    for($i=0;$i<$hashCount;$i++)
                        $hashes[] = swapEndian(substr($payload, -64*($i+2), 64));
                    $blocks = [
                        'version' => hexdec(swapEndian(substr($payload, 0, 8))),
                        'hash count' => $hashCount,
                        'block header hashes' => $hashes,
                        'stop hash' => swapEndian(substr($payload, -64)),
                    ];
					sendMessage($socket,'inv', $payload);	
					break;
                case 'tx':
                    $txInCount = parseVarInt(substr($payload, 8));
                    $readIndent = 8 + varIntSize(substr($payload, 8));
                    for($i=0;$i<$txInCount;$i++){
                        $sigSize = parseVarInt(substr($payload, $readIndent + 72)) * 2;
                        $sigSizeLen = varIntSize(substr($payload, $readIndent + 72));
                        $tx_in[] = [
                            'previous_output_id' => substr($payload, $readIndent, 64),
                            'previous_output_v' => hexdec(swapEndian(substr($payload, $readIndent + 64, 8))),
                            'ScriptSig Size' => $sigSize/2,
                            'ScriptSig' => substr($payload, $readIndent + 72 + $sigSizeLen, $sigSize),
                            'Sequence' => substr($payload, $readIndent + 72 + $sigSizeLen + $sigSize, 8),
                        ];
                        $readIndent += 80 + $sigSizeLen + $sigSize;
                    }
                    $txOutCount = parseVarInt(substr($payload, $readIndent));
                    $readIndent = $readIndent + varIntSize(substr($payload, $readIndent));
                    for($i=0;$i<$txOutCount;$i++){
                        $sigSize = parseVarInt(substr($payload, $readIndent + 16)) * 2;
                        $sigSizeLen = varIntSize(substr($payload, $readIndent + 16));
                        $tx_out[] = [
                            'value' => substr($payload, $readIndent, 16),
                            'pk_script length' => $sigSize/2,
                            'pk_script' => substr($payload, $readIndent + 16 + $sigSizeLen, $sigSize),
                        ];
                        $readIndent += 16 + $sigSizeLen + $sigSize;
                    }
                    $lockTime = substr($payload, $readIndent, 8);
                    $transaction = [
                        'version' => hexdec(swapEndian(substr($payload, 0, 8))),
                        'tx_in count' => $txInCount,
                        'tx_in' => $tx_in,
                        'tx_out count' => $txOutCount,
                        'tx_out' => $tx_out,
                        'lock_time' => $lockTime,
                    ];
                    print_r($transaction);
                    break;
                case 'verack':
                    break;
                case 'addr':
                    $addrCount = parseVarInt($payload);
                    for($i=0;$i<$addrCount;$i++){
                        $address = [
                            'time' => hexdec(swapEndian(substr($payload, $i*60 + 2, 8))),
                            'services' => byteSpaces(substr($payload, $i*60 + 10, 16)),
                            'ip' => parseIp(substr($payload, $i*60 + 26, 32)),
                            'port' => hexdec(substr($payload, $i*60 + 58, 4)),
                        ];
                        print_r($address);
                    }
                    break;
                case 'getdata':
                    sendMessage($socket,'notfound', $payload);	
                    break;
                case 'ping':
                    print_r(['nonce' => $payload]);
					sendMessage($socket,'pong', $payload);
					break;
                case 'notfound':
					break;
                case 'getheaders':
                    $hashCount = parseVarInt(substr($payload, 8));
                    for($i=0;$i<$hashCount;$i++)
                        $hashes[] = swapEndian(substr($payload, -64*($i+2), 64));
                    $blocks = [
                        'version' => hexdec(swapEndian(substr($payload, 0, 8))),
                        'hash count' => $hashCount,
                        'block header hashes' => $hashes,
                        'stop hash' => substr($payload, -64),
                    ];
                    // should respond with a headers message
                    break;
                case 'headers':
                    break;
                case 'block':
                    $block = [
                        'version' => hexdec(swapEndian(substr($payload, 0, 8))),
                        'previous block header hash' => swapEndian(substr($payload, 8, 64)),
                        'merkle root hash' => swapEndian(substr($payload, 72, 64)),
                        'time' => hexdec(swapEndian(substr($payload, 136, 8))),
                        'nBits' => substr($payload, 144, 8),
                        'nonce' => substr($payload, 152, 8),
                        'txn_count' => parseVarInt(substr($payload, 160)),
                    ];
                    print_r($block);
                    break;
                case 'getaddr':
                    // should respond with an addr message but we don't know anyone in the network :D
                    break;
                case 'sendheaders':
                    break;
                case 'feefilter':
                    break;
                case 'mempool':
                    sendMessage($socket,'inv', '');
					break;
			}
        }
        usleep($config['microSleep']);
    }
}
