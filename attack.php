<?php

function webscan_for(){
    //get拦截规则
    $getfilter = "<[^>]*?=[^>]*?&#[^>]*?>|\\b(alert\\(|confirm\\(|expression\\(|prompt\\()|<[^>]*?\\b(onerror|onmousemove|onload|onclick|onmouseover)\\b[^>]*?>|^\\+\\/v(8|9)|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
    //post拦截规则
    $postfilter = "<[^>]*?=[^>]*?&#[^>]*?>|\\b(alert\\(|confirm\\(|expression\\(|prompt\\()|<[^>]*?\\b(onerror|onmousemove|onload|onclick|onmouseover)\\b[^>]*?>|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
    //cookie拦截规则
    $cookiefilter = "\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
    $requestfilter = "<[^>]*?=[^>]*?&#[^>]*?>|\\b(alert\\(|confirm\\(|expression\\(|prompt\\()|<[^>]*?\\b(onerror|onmousemove|onload|onclick|onmouseover)\\b[^>]*?>|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
    //referer获取
    //$webscan_referer = empty($_SERVER['HTTP_REFERER']) ? array() : array('HTTP_REFERER' => $_SERVER['HTTP_REFERER']);
    /**
     * 开始检查
     */
    if (!defined('WEBSCAN_SWITCH')) define('WEBSCAN_SWITCH', 0);
    //if (WEBSCAN_SWITCH) {
    foreach ($_GET as $key => $value) {
        webscan_StopAttack($key, $value, $getfilter, "GET");
    }
    foreach ($_POST as $key => $value) {
        webscan_StopAttack($key, $value, $postfilter, "POST");
    }
    foreach ($_COOKIE as $key => $value) {
        webscan_StopAttack($key, $value, $cookiefilter, "COOKIE");
    }
    foreach ($_REQUEST as $key => $value) {
        webscan_StopAttack($key, $value, $requestfilter, "REQUEST");
    }
    //}
}

function str_check($str) {
    //$str = str_replace("_", "\_", $str); // 把 '_'过滤掉
    //$str = str_replace("%", "\%", $str); // 把 '%'过滤掉
    $str = preg_replace('/[\x00-\x08]|[\x0b-\x0c]|[\x0e-\x1e]/', '', $str);
    return $str;
}

/**
 *  攻击检查拦截
 */
function webscan_StopAttack($StrFiltKey, $StrFiltValue, $ArrFiltReq, $method) {
    $requestFilterArr = [
        'UPDATE','INSERT','UNION','INTO','SET','SELECT',
        'DELETE','VALUES','FROM','CREATE', 'ALTER','DROP',
        'TRUNCATE','TABLE','DATABASE','SLEEP',
    ];
    $tableFilter = [
        'C_BET','K_BET', 'K_USER_CASH_RECORD','K_USER','BET_RECORD',
        'PAY_SET','K_BANK','PAY_OUT_SET','SYS_ADMIN', ';', '`','SCRIPT',
        '%3B', '%BB', '%BC', '%BD', '%BF', '%C2', '%C3', '%C4',
        '%C5', '%C6', '%C7', '%CE', '%CF', '%D1', '%D4', '%D5',
        '%D6', '%D8', '%E3', '%E4', '%E5', '%E6', '%E7', '%EB',
        '%EE', '%EF', '%F1', '%F4', '%F5', '%F6', '%F8', '%FB',
        '%FF',
    ];
    $StrFiltValue = str_check($StrFiltValue);
    $StrFiltValue = strtoupper(webscan_arr_foreach($StrFiltValue));
    if (preg_match("/" . $ArrFiltReq . "/is", $StrFiltValue) == 1) {
        webscan_slog(array('ip' => attack_get_ip(), 'time' => strftime("%Y-%m-%d %H:%M:%S"), 'page' => $_SERVER["PHP_SELF"], 'method' => $method, 'rkey' => $StrFiltKey, 'rdata' => $StrFiltValue, 'user_agent' => $_SERVER['HTTP_USER_AGENT'], 'request_url' => $_SERVER["REQUEST_URI"]));
        exit(webscan_pape());
    }
    if (preg_match("/" . $ArrFiltReq . "/is", $StrFiltKey) == 1) {
        webscan_slog(array('ip' => attack_get_ip(), 'time' => strftime("%Y-%m-%d %H:%M:%S"), 'page' => $_SERVER["PHP_SELF"], 'method' => $method, 'rkey' => $StrFiltKey, 'rdata' => $StrFiltKey, 'user_agent' => $_SERVER['HTTP_USER_AGENT'], 'request_url' => $_SERVER["REQUEST_URI"]));
        exit(webscan_pape());
    }
    foreach ($tableFilter as $val){
        if (strpos($StrFiltValue, $val) !== false){
            webscan_slog(array('ip' => attack_get_ip(), 'time' => strftime("%Y-%m-%d %H:%M:%S"), 'page' => $_SERVER["PHP_SELF"], 'method' => $method, 'rkey' => $StrFiltKey, 'rdata' => $StrFiltKey, 'user_agent' => $_SERVER['HTTP_USER_AGENT'], 'request_url' => $_SERVER["REQUEST_URI"]));
            exit(webscan_pape());
        }
    }
    foreach ($requestFilterArr as $val){
        if (preg_match("/\b" . $val . "\b/is", $StrFiltValue) == 1){
            if($val == 'TABLE' && preg_match_all("/(<\/|<)\b" . $val . "\b/is", $StrFiltValue) == preg_match_all("/\b" . $val . "\b/is", $StrFiltValue)){
                continue;
            }
            webscan_slog(array('ip' => attack_get_ip(), 'time' => strftime("%Y-%m-%d %H:%M:%S"), 'page' => $_SERVER["PHP_SELF"], 'method' => $method, 'rkey' => $StrFiltKey, 'rdata' => $StrFiltKey, 'user_agent' => $_SERVER['HTTP_USER_AGENT'], 'request_url' => $_SERVER["REQUEST_URI"]));
            exit(webscan_pape());
        }
    }
    $crucial = ["[u|U](%[0-9a-zA-Z]+)?[p|P](%[0-9a-zA-Z]+)?[d|D](%[0-9a-zA-Z]+)?[a|A](%[0-9a-zA-Z]+)?[t|T](%[0-9a-zA-Z]+)?[e|E]",
    "[s|S](%[0-9a-zA-Z]+)?[e|E](%[0-9a-zA-Z]+)?[l|L](%[0-9a-zA-Z]+)?[e|E](%[0-9a-zA-Z]+)?[c|C](%[0-9a-zA-Z]+)?[t|T]"];
    foreach ($crucial as $value) {
        if (preg_match("/" . $value . "/is" , urlencode($StrFiltValue)) == 1) {
            webscan_slog(array('ip' => attack_get_ip(), 'time' => strftime("%Y-%m-%d %H:%M:%S"), 'page' => $_SERVER["PHP_SELF"], 'method' => $method, 'rkey' => $StrFiltKey, 'rdata' => $StrFiltKey, 'user_agent' => $_SERVER['HTTP_USER_AGENT'], 'request_url' => $_SERVER["REQUEST_URI"]));
            exit(webscan_pape());
        }
    }
}
/**
 *  参数拆分
 */
function webscan_arr_foreach($arr) {
    static $str;
    if (!is_array($arr)) {
        return $arr;
    }
    foreach ($arr as $key => $val) {

        if (is_array($val)) {

            webscan_arr_foreach($val);
        } else {

            $str[] = $val;
        }
    }
    return implode($str);
}

/**
 *  数据统计回传
 */
function webscan_slog($logs) {
    $data = json_encode($logs);
    //WEBSCAN_LOG_DIR
    runattacklog($data, 0);
}

//写入
//写运行日志
function runattacklog($log, $halt = 0) {
    $file = "attacklog";
    $mtime = explode(' ', microtime());
    $yearmonth = date('Ym', $mtime[1]);
    $logdir = WEBSCAN_LOG_DIR_WEB;
    if (!is_dir($logdir))
        mkdir($logdir, 0777);
    $logfile = $logdir . $yearmonth . '_' . $file . '.php';
    if (@filesize($logfile) > 2048000) {
        $dir = opendir($logdir);
        $length = strlen($file);
        $maxid = $id = 0;
        while ($entry = readdir($dir)) {
            if (strexists($entry, $yearmonth . '_' . $file)) {
                $id = intval(substr($entry, $length + 8, -4));
                $id > $maxid && $maxid = $id;
            }
        }
        closedir($dir);
        $logfilebak = $logdir . $yearmonth . '_' . $file . '_' . ($maxid + 1) . '.php';
        @rename($logfile, $logfilebak);
    }
    $log = trim($log) . "\n";
    if ($fp = @fopen(dirname(__FILE__).'/'.$logdir.'/'.$logfile, 'a')) {
        @flock($fp, 2);
        fwrite($fp, "<?PHP exit;?>\t" . str_replace(array('<?', '?>', "\r", "\n"), '', $log) . "\n");
        fclose($fp);
    }
    if ($halt)
        exit();
}

/**
 *  防护提示页
 */
function webscan_pape() {
    //header('Location: /');
    echo '<script>alert("您提交的内容有敏感字符串,请检查后重新提交");</script>';
}

/**
 * 获取IP
 */
function attack_get_ip(){
    $realip = '';
    $unknown = 'unknown';
    if (isset($_SERVER)){
        if(isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR']) && strcasecmp($_SERVER['HTTP_X_FORWARDED_FOR'], $unknown)){
            $arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach($arr as $ip){
                $ip = trim($ip);
                if ($ip != 'unknown'){
                    $realip = $ip;
                    break;
                }
            }
        }else if(isset($_SERVER['HTTP_CLIENT_IP']) && !empty($_SERVER['HTTP_CLIENT_IP']) && strcasecmp($_SERVER['HTTP_CLIENT_IP'], $unknown)){
            $realip = $_SERVER['HTTP_CLIENT_IP'];
        }else if(isset($_SERVER['REMOTE_ADDR']) && !empty($_SERVER['REMOTE_ADDR']) && strcasecmp($_SERVER['REMOTE_ADDR'], $unknown)){
            $realip = $_SERVER['REMOTE_ADDR'];
        }else{
            $realip = $unknown;
        }
    }else{
        if(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), $unknown)){
            $realip = getenv("HTTP_X_FORWARDED_FOR");
        }else if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), $unknown)){
            $realip = getenv("HTTP_CLIENT_IP");
        }else if(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), $unknown)){
            $realip = getenv("REMOTE_ADDR");
        }else{
            $realip = $unknown;
        }
    }
    $realip = preg_match("/[\d\.]{7,15}/", $realip, $matches) ? $matches[0] : $unknown;
    return $realip;
}

webscan_for();

?>