# CryptoJS 3.x AES 的PHP和GO版本，实现服务端与前端的数据加解密
这是一个JS前端与后端加密json数据的解决方案，前端适用于CryptoJS 3.x版本，后端PHP适用openssl_decrypt的aes-256-cbc算法，GO语言适用libmcrypt的rijndael-128
算法

## 使用
JS
<pre>
<script type="text/javascript" src="aes.js"></script>
<script type="text/javascript" src="aes-json-format.js"></script>
var passphrase = 'abcde';
var value = '{"code":200,"msg":"ok"}';
var jsonString = CryptoJS.AES.encrypt(JSON.stringify(value), passphrase, {format: CryptoJSAesJson}).toString();
var originData = CryptoJS.AES.decrypt(jsonString, passphrase, {format: CryptoJSAesJson}).toString(CryptoJS.enc.Utf8);
</pre>

PHP
<pre>
$passphrase = 'abcde';
$value = '{"code":200,"msg":"ok"}';
$jsonString = cryptoJsAesEncrypt($passphrase, $value)
$originData = cryptoJsAesDecrypt($passphrase, $jsonString)
</pre>

GO
<pre>
import (
	"library/mcrypt"
)
passphrase := "abcde"
value := `{"code":200,"msg":"ok"}`;
jsonString := mcrypt.CryptoJsAesEncrypt(passphrase, value)
originData := mcrypt.CryptoJsAesDecrypt(passphrase, jsonString)
</pre>

## 感谢
[cryptojs-aes-php](https://github.com/brainfoolong/cryptojs-aes-php)
