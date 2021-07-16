<?php

/**
 *  XRCSRF - Simple CSRF class for PHP.
 *
 *  @author Uğur PEKESEN <xaron.job@gmail.com>
 *  @version 1.0.0
 */

namespace XRCSRF;

class XRCSRF {
    private $secret = substr(str_shuffle(str_repeat("abcdefghijklmnopqrstuvwxyz", 15)), 0, 15);
    public function __construct() {
        if(!isset($_SESSION)) session_start();
        $_SESSION[$this->secret] = array(substr(str_shuffle(str_repeat("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 48)), 0, 48),time()+3600);
        set_exception_handler(function($exception) {
            self::abort(500, $exception->getMessage());
        });
        header("x-secured-by: XRCSRF/v1.0");
        self::requirements();
    }

    private static function secret($x) {
        foreach($x as $post => $postdata){
            if(strlen($post) == 15){
                if($_SESSION[$post] != NULL){
                    if($x[$post] == $_SESSION[$post][0]){
                        return array($_SESSION[$post][1], $post);
                    }else{
                        return array(-1, -1);
                    }
                }
            }
        }
        return array(-1, -1);
    }

    private static function isRightSecret($x) {
        $secarray = self::secret($x);
        if($secarray[0] == -1 || $secarray[0]-time() <= 0){
            if($secarray[0] == -1){
                self::abort(777, "There was an error while processing your request. Please try again.");
            }else{
                unset($_SESSION[$secarray[1]]);
                self::abort(777, "The page has timed out. Please try again.");
                return -1;
            }
        }else{
            return 1;
        }
        return 0;
    }

    public function checkCsrf($post) {
        return (self::isRightSecret($post) != 1 ? false : true);
    }

    private static function abort(int $status, string $message = null) {
        $statusses = ['404', '403', '500', '777'];
        if(in_array($status, $statusses)) {
            header('HTTP/1.0 '.$status.' Forbidden');
            die('<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>'.$status.' - XRCSRF</title> <style type="text/css">*{transition: all .6s}html{height: 100%}body{font-family: Lato, sans-serif; color: #888; margin: 0}#main{display: table; width: 100%; height: 100vh; text-align: center}.fof{display: table-cell; vertical-align: middle}h1{font-size: 50px; display: inline-block; padding-right: 12px; animation: type .5s alternate infinite}h3{font-size: 30px; padding-right: 12px; animation: type .5s alternate infinite}@keyframes type{from{box-shadow: inset -3px 0 0 #888}to{box-shadow: inset -3px 0 0 transparent}}</style></head><body><div id="main"> <div class="fof"> <h1>'.$status.'</h1>'.($message ? '<h3>'.$message.'</h3>' : '').'<br/></br></br></br></br>Ray ID: '.md5($status.$message.time()).' - Secured by <a href="https://github.com/xaronnn/XRCSRF" target="_blank">XRCSRF</a> </div></div></body></html>');
        } else {
            return false;
        }
    }

    protected static function requirements() {
        if(version_compare('7.1', PHP_VERSION) > 0) {
            self::abort(777, 'Please use PHP version >= 7.1');
        }
        if(!extension_loaded('curl')) {
            self::abort(777, 'Unable to find cURL extension');
        }
        if(!extension_loaded('openssl')) {
            self::abort(777, 'Unable to find OpenSSL extension');
        }
    }
    
}