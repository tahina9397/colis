<?php

use YoHang88\LetterAvatar\LetterAvatar;
use Intervention\Image\ImageManagerStatic as Image;

class Application_Model_User
{

    const NAMESPACE_DEFAULT = 'admin';
    protected $_namespace;

    public function __construct($namespace = self::NAMESPACE_DEFAULT)
    {
        $this->_namespace  = $namespace;
    }

    public function isConnected()
    {
        $storage = new Zend_Auth_Storage_Session($this->_namespace);
        if (empty($storage->read()))
            return false;

        if ($storage != NULL && (int)$storage->read()->id)
            return true;
        return false;
    }

    public function logout()
    {
        Application_Model_Global::pupdate(TABLE_PREFIX . "users", array('online' => '0'), "id = :id", array(":id" => $this->getId()));
        $storage = new Zend_Auth_Storage_Session($this->_namespace);
        $storage->clear();
    }

    public function getData()
    {
        $storage = new Zend_Auth_Storage_Session($this->_namespace);

        $r = $storage->read();

        $r->droits = Application_Model_Access::getDroitAccessByIdUser($r->id);

        /* abonnement */
        $r->subscription = self::getSubscription($r->id);

        return $r;
    }

    public function getStorage()
    {
        return new Zend_Auth_Storage_Session($this->_namespace);
    }

    public function getId()
    {
        $storage = new Zend_Auth_Storage_Session($this->_namespace);
        $data = $storage->read();
        if ($data)
            return (int)$data->id;
        return 0;
    }

    public function getUserByHash($hash)
    {
        return Application_Model_Global::pselectRow(TABLE_PREFIX . "users", 'id', " hash=:hash ", array(":hash" => $hash));
    }

    public function get($user_id)
    {
        $where = "u.id = :user_id ";
        $sql = " 
 			SELECT 
 				u.*
 				,tu.privilege
 			FROM " . TABLE_PREFIX . "users u 
 			INNER JOIN " . TABLE_PREFIX . "type_users tu ON (u.id_type_user = tu.id)
 			WHERE $where 
 		";

        $user = Application_Model_Global::pqueryRow($sql, array(":user_id" => $user_id));
    
        return $user;
    }

    public function getLoginStatus($table, $fk, $fk_value)
    {
        $response_array = array(
            'status' => 'safe',
            'message' => null
        );

        //attempt to retrieve latest failed login attempts
        $latest_failed_logins = null;
        $latest_failed_attempt_datetime = null;

        $sql = "SELECT MAX(id) as max_id, MAX(attempted_at) AS attempted_at FROM $table WHERE $fk=:$fk";
        $latest_failed_attempt = Application_Model_Global::pqueryRow($sql, array(":$fk" => $fk_value));
        $latest_failed_attempt_datetime = (int) date('U', strtotime($latest_failed_attempt['attempted_at']));
        $latest_failed_attempt_id = (int)$latest_failed_attempt['max_id'];

        $latest_status = 'safe';
        if ($latest_failed_attempt_id) {
            $ulogin = Application_Model_Global::pselectRow($table, "status", " id=:id ", array(':id' => $latest_failed_attempt_id));
            $latest_status = $ulogin['status'];
        }

        $throttle_limit = 3;
        $throtlle_delay = 900;

        //get all failed attempst within time frame
        $sql = "SELECT count(id) AS number FROM $table WHERE attempted_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE) AND $fk=:$fk";
        $get_number = Application_Model_Global::pqueryRow($sql, array(":$fk" => $fk_value));
        $number_recent_failed = (int)$get_number['number'];

        //if number of failed attempts is >= throttle_limit, react
        if ($number_recent_failed >= $throttle_limit or $latest_status == 'delay') {

            //find the time of the next allowed login
            $next_login_minimum_time = $latest_failed_attempt_datetime + $throtlle_delay;

            //if the next allowed login time is in the future, calculate the remaining delay
            if (time() < $next_login_minimum_time) {
                $remaining_delay = $next_login_minimum_time - time();
                // add status to response array
                $response_array['status'] = 'delay';
                $response_array['message'] = gmdate("i:s", $remaining_delay);
                Application_Model_Global::pupdate($table, array('status' => 'delay'), " id=:id ", array(':id' => $latest_failed_attempt_id));
            } else {
                // delay has been passed, safe to login
                $response_array['status'] = 'safe';
                Application_Model_Global::pupdate($table, array('status' => 'safe'), " id=:id ", array(':id' => $latest_failed_attempt_id));
            }
        }

        return $response_array;
    }

    public function getInfoUserConnected()
    {
        $users = new Application_Model_User("admin");
        $data = $users->getData();

        return $data;
    }
}
