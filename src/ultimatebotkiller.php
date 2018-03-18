<?php
/**
 *  UltimateBotKiller - PHP Library For Block 99.99% of Malicious Bots.
 *
 *  @author Alemalakra
 *  @version 3.0
 */

namespace Alemalakra\UltimateBotKiller;

// NGINX PHP-FPM and No-Supported Versions.
if (!function_exists('getallheaders')) { 
    function getallheaders() {
       $headers = array (); 
       foreach ($_SERVER as $name => $value) { 
           if (substr($name, 0, 5) == 'HTTP_') { 
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value; 
           } 
       } 
       return $headers; 
    } 
} 
require('Packer.php');

class UBK {
	function __construct() {
		@session_start();
		@ob_start();
	}
	function gua() {
		if (isset($_SERVER['HTTP_USER_AGENT'])) {
			return $_SERVER['HTTP_USER_AGENT'];
		}
		return md5(rand());
	}
	function cutGua($string) {
		$five = substr($string, 0, 4);
		$last = substr($string, -3);
		return md5($five.$last);
	}
	function getHeaders() {
		return session_id() . count(getallheaders()) . count($_SERVER) . count(getallheaders()) . count($_SERVER) . count(getallheaders());
	}
	function getIP() {
		if (isset($_SERVER['REMOTE_ADDR'])) {
			$IP = $_SERVER['REMOTE_ADDR'];
			$IP = str_replace('.', "", $IP);
			$IP = str_replace(':', "", $IP);
			$IP = str_replace('::', "", $IP);
			return $IP;
		}
		return "127001";
	}
	function getToken() {
		$token = md5(uniqid(rand(), TRUE));
		$token = $this->getIP() . $this->getHeaders() . $token . "rf9784" . $this->cutGua($this->gua());
		return $token;
	}
	function getCSRF() {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				return $_SESSION['token'];
			} else {
				$token = md5(uniqid(rand(), TRUE));
				$_SESSION['token'] = $this->getToken();
				$_SESSION['token_time'] = time();
				return $_SESSION['token'];
			}
		} else {
			$token = md5(uniqid(rand(), TRUE));
			$_SESSION['token'] = $this->getToken();
			$_SESSION['token_time'] = time();
			return $_SESSION['token'];
		}
	}
	function verifyCSRF($Value) {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				if ($Value == $_SESSION['token']) {
					$Explode = explode('rf9784', $_SESSION['token']);
					$gua = $Explode[1];
					if ($this->cutGua($this->gua()) == $gua) {
						// Validated, Done!
						for ($i=0; $i < rand(5,20); $i++) { 
							header('UBK_' . rand() . ': ' . rand());
						}
						unset($_SESSION['token']);
						unset($_SESSION['token_time']);
						return true;
					}
					unset($_SESSION['token']);
					unset($_SESSION['token_time']);
					return false;
				}
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	function js($jsStr) {
		$jsStr = preg_replace('~[^"\'\(]// ([^\r\n]*)[^"\'\)]~', '/*$1 */', $jsStr);
		$jsStr = str_replace("\r", "", $jsStr);
		$jsStr = str_replace("\n", "", $jsStr);
		$jsStr = str_replace("\t", "", $jsStr);
		$jsStr = str_replace(" = ", "=", $jsStr);
		$jsStr = str_replace(") {", "){", $jsStr);
		$jsStr = str_replace(" ( ", "(", $jsStr);
		$jsStr = str_replace(" ) ", ")", $jsStr);
		$jsStr = str_replace("; ", ";", $jsStr);
		$jsStr = str_replace("if ", "if", $jsStr);
		$jsStr = str_replace("for ", "for", $jsStr);
		$jsStr = str_replace(" >= ", ">=", $jsStr);
		$jsStr = str_replace(" + ", "+", $jsStr);
		$jsStr = str_replace(" - ", "-", $jsStr);
		$jsStr = str_replace(" * ", "*", $jsStr);
		$jsStr = str_replace(" / ", "/", $jsStr);
		$jsStr = str_replace(" || ", "||", $jsStr);
		$jsStr = str_replace(" && ", "&&", $jsStr);
		$jsStr = str_replace("try ", "try", $jsStr);
		$jsStr = str_replace(", ", ",", $jsStr);
		$jsStr = str_replace(" == ", "==", $jsStr);
		$jsStr = str_replace(" != ", "!=", $jsStr);
		$jsStr = str_replace(": ", ":", $jsStr);
		$jsStr = str_replace("  ", "", $jsStr);
		$jsStr = str_replace("   ", "", $jsStr);
		$jsStr = str_replace("    ", "", $jsStr);
		return '<script>' . $jsStr . '</script>';
	}
	function generateRandomString($length = 10) {
	    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	    $charactersLength = strlen($characters);
	    $randomString = '';
	    for ($i = 0; $i < $length; $i++) {
	        $randomString .= $characters[rand(0, $charactersLength - 1)];
	    }
	    return $randomString;
	}
	function server($string) {
		if (isset($_SERVER[$string])) {
			return $_SERVER[$string];
		}
		return "";
	}
	function cutCookie($string) {
		$five = substr($string, 0, 4);
		$last = substr($string, -3);
		return md5($five.$last);
	}
	function getNameCookie() {
		$String = $this->server('HTTP_ACCEPT_LANGUAGE');
		$String = $String . $this->server('HTTP_USER_AGENT');
		$String = $String . $this->server('SCRIPT_FILENAME');
		$String = $String . $this->server('HTTP_ACCEPT_ENCODING');
		$String = $String . $this->server('HTTP_ACCEPT');
		$String = $String . $this->cutGua($this->gua());
		return $this->cutCookie(hash('sha512', $String)); // 128 Chars.
	}
	function setCookie() {
		$boolean = rand(0,1) == 1;
		if ($boolean == true) {
			return 'document.cookie = '. "'" .'UBK-'. $this->getNameCookie() .'='.$this->getCSRF(). "'" . ';';
		}
		return 'document.cookie = "UBK-'. $this->getNameCookie() .'='.$this->getCSRF().'";';
	}
	function getCode() {
		$k = "function botCheck(){var botPattern='(googlebot\/|Googlebot-Mobile|Googlebot-Image|Google favicon|Mediapartners-Google|bingbot|slurp|java|wget|curl|Commons-HttpClient|Python-urllib|libwww|httpunit|nutch|phpcrawl|msnbot|jyxobot|FAST-WebCrawler|FAST Enterprise Crawler|biglotron|teoma|convera|seekbot|gigablast|exabot|ngbot|ia_archiver|GingerCrawler|webmon |httrack|webcrawler|grub.org|UsineNouvelleCrawler|antibot|netresearchserver|speedy|fluffy|bibnum.bnf|findlink|msrbot|panscient|yacybot|AISearchBot|IOI|ips-agent|tagoobot|MJ12bot|dotbot|woriobot|yanga|buzzbot|mlbot|yandexbot|purebot|Linguee Bot|Voyager|CyberPatrol|voilabot|baiduspider|citeseerxbot|spbot|twengabot|postrank|turnitinbot|scribdbot|page2rss|sitebot|linkdex|Adidxbot|blekkobot|ezooms|dotbot|Mail.RU_Bot|discobot|heritrix|findthatfile|europarchive.org|NerdByNature.Bot|sistrix crawler|ahrefsbot|Aboundex|domaincrawler|wbsearchbot|summify|ccbot|edisterbot|seznambot|ec2linkfinder|gslfbot|aihitbot|intelium_bot|facebookexternalhit|yeti|RetrevoPageAnalyzer|lb-spider|sogou|lssbot|careerbot|wotbox|wocbot|ichiro|DuckDuckBot|lssrocketcrawler|drupact|webcompanycrawler|acoonbot|openindexspider|gnam gnam spider|web-archive-net.com.bot|backlinkcrawler|coccoc|integromedb|content crawler spider|toplistbot|seokicks-robot|it2media-domain-crawler|ip-web-crawler.com|siteexplorer.info|elisabot|proximic|changedetection|blexbot|arabot|WeSEE:Search|niki-bot|CrystalSemanticsBot|rogerbot|360Spider|psbot|InterfaxScanBot|Lipperhey SEO Service|CC Metadata Scaper|g00g1e.net|GrapeshotCrawler|urlappendbot|brainobot|fr-crawler|binlar|SimpleCrawler|Livelapbot|Twitterbot|cXensebot|smtbot|bnf.fr_bot|A6-Indexer|ADmantX|Facebot|Twitterbot|OrangeBot|memorybot|AdvBot|MegaIndex|SemanticScholarBot|ltx71|nerdybot|xovibot|BUbiNG|Qwantify|archive.org_bot|Applebot|TweetmemeBot|crawler4j|findxbot|SemrushBot|yoozBot|lipperhey|y!j-asr|Domain Re-Animator Bot|AddThis)';var re=new RegExp(botPattern,'i');var userAgent=navigator.userAgent;if(re.test(userAgent)){return!0}else{return!1}} ";
		$d = 'if (Date()) { var d = Date(); var a = d.split(" ");if (a.length > 5) { if (botCheck() == false) { '; // codigo // }}
		$r = $k . PHP_EOL . $d . $this->setCookie() . "document.getElementById('" . $this->cutGua($this->gua()) . "').value = '". $this->getCSRF() ."'; document.getElementById('" . $this->cutGua($this->gua()) . "').name = '". $this->getCSRF() ."'; }}}";
		return $r;
	}
	function getValueInput($name) {
		foreach ($_SESSION as $key => $value) {
			if (strpos($key, 'NF-') !== false) {
			    $key = str_replace('NF-', '', $key);
			    if ($key == $name) {
			    	if (isset($_REQUEST[$value])) {
			    		return $_REQUEST[$value];
			    	}
			    	return false;
			    }
			}
		}
	}
	function getNameInput($Name) {
		$k = $this->generateRandomString(rand(15, 40));
		$_SESSION['NF-' . $Name] = $k;
		$this->FormNames[$k] = $Name;
		return $k;
	}
	function getInputBotKiller($_s) {
		$boolean = rand(0,1) == 1;
		if ($boolean == true) {
			return '<input type="hidden" id='. "'" . $this->cutGua($this->gua()) . "'" . " />" . $this->js($_s);
		}
		return "<input type='hidden' id=" . '"' . $this->cutGua($this->gua()) . '"' . " />" . $this->js($_s);
	}
	function validateForm() {
		if (!(isset($_POST[$this->getCSRF()]))) {
			return false;
		}
		if (!($this->verifyCSRF($_POST[$this->getCSRF()]))) {
			return false;
		}
		if (!(isset($_COOKIE['UBK-' . $this->getNameCookie()]))) {
			return false;
		}
		foreach ($_COOKIE as $key => $value) {
			if (strpos($key, 'UBK-') !== false) {
			    setcookie ($key, "", time() - 3600);
			}
		}
		return true;
	}
}

?>
