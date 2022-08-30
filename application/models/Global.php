<?php

class Application_Model_Global {
    /* PREPAREE */

    public function pquery($sql, $parametres = array()) {
        global $db;

        try {
            $state = $db->prepare($sql);
            $state->execute($parametres);
            $data = $state->fetchAll();
            return $data;
        } catch (Exception $e) {
            return false;
        }
    }

    public function pqueryRow($sql, $parametres = array()) {
        global $db;
        try {
            $state = $db->prepare($sql);
            $state->execute($parametres);
            $data = $state->fetch();
            return $data;
        } catch (Exception $e) {
            return false;
        }
    }

    public function pdelete($table, $where, $where_params = array()) {
        global $db;
        try {
            $sql = "DELETE FROM $table WHERE $where";
            $state = $db->prepare($sql);
            $state->execute($where_params);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public function pselect($table_name, $champs = '', $where = 1, $parametres = array()) {
        global $db;
        if ($champs != ''){
            if($where != 1){
                $sql = " SELECT $champs FROM $table_name WHERE $where ";
            }else{
                $sql = " SELECT $champs FROM $table_name WHERE 1 ";
            }
        }else{
            if($where != 1){
                $sql = " SELECT * FROM $table_name WHERE $where ";
            }else{
                $sql = " SELECT * FROM $table_name WHERE 1 ";
            }
        }

        $state = $db->prepare($sql);
        $state->execute($parametres);
        $data = $state->fetchAll();
        return $data;
    }

    public function pselectRow($table_name, $champs = '', $where = 1, $parametres = array()) {
        global $db;
        if ($champs != ''){
            if($where != 1){
                $sql = " SELECT $champs FROM $table_name WHERE $where ";
            }else{
                $sql = " SELECT $champs FROM $table_name WHERE 1 ";
            }
        }else{
            if($where != 1){
                $sql = " SELECT * FROM $table_name WHERE $where ";
            }else{
                $sql = " SELECT * FROM $table_name WHERE 1 ";
            }
        }

        $state = $db->prepare($sql);
        $state->execute($parametres);
        $data = $state->fetch();
        return $data;
    }

    public function pupdate($table, $data, $where, $where_params = array()) {
        global $db; 
        try {
            $fields = array_keys($data);
            $values_fields = array_values($data);

            // fields array with two dots
            $fields_arr = array();
            if(!empty($fields)){
                foreach ($fields as $k => $item) {
                    $fields_arr[] = " $item = :$item ";
                }
            }

            // bind fields params with two dots
            $data_bind_params = array();
            if(!empty($data)){
                foreach ($data as $k => $item) {
                    $data_bind_params[':'.$k] = $item;    
                }
            }

            $bind_params = array_merge($data_bind_params, $where_params);
            $sql_update = "UPDATE $table set ".implode(',', $fields_arr)." WHERE $where";
            $state = $db->prepare($sql_update);
            $state->execute($bind_params);
            return true;
        } 
        catch(Exception $e)
        {
            echo "<pre>";
            print_r($e);
            echo "</pre>";
            die;
            return false;
        }
    }

    public function insert($table, $data) {
        global $db;
        try {
            $ret = $db->insert($table, $data);
            return $ret;
        } catch (Exception $e) {
            echo "<pre>";
            print_r($e);
            echo "</pre>";
            die;
            return false;
        }
    }

    public function pexecute($sql, $parametres) {
        global $db;
        try {
            $state = $db->prepare($sql);
            $state->execute($parametres);
            return true;
        }catch(Exception $e){
            echo "<pre>";
            print_r($e);
            echo "</pre>";
            die;
            return false;
        }
    }

    /* END PREPAREE */

    public static function getContenu($table, $id_language, $id, $where = NULL) {
        global $db;
        $sql = "
		SELECT
		T.*,
		TL.*
		FROM
		$table T
		INNER JOIN " . $table . "_multilingual TL ON T.id = TL.$id
		WHERE
		TL.id_language = :id_language
		$where
		";
        $data = Application_Model_Global::pquery($sql, array(":id_language"=>$id_language));
        return $data;
    }

    public static function getContenuRow($table, $table_lang, $id_lang, $id_fk_name, $where = NULL) {
        global $db;
        $sql = "
        SELECT
        T.*,
        TL.*
        FROM
        $table T
        INNER JOIN $table_lang TL ON (T.id = TL.$id_fk_name AND TL.id_language = :id_lang )
        WHERE
        $where
        ";
        $data =  Application_Model_Global::pqueryRow($sql, array(":id_lang"=>$id_lang));
        return $data;
    }

    public static function getContenuById($table, $id_language, $id_fk_name, $id, $where = NULL) {
        global $db;
        $sql = "
        SELECT
        T.* AS T.id
        T.*,
        TL.*
        FROM
        $table T
        INNER JOIN " . $table . "_multilingual TL ON (T.id = TL.$id_fk_name AND TL.id_language = :id_language)
        WHERE
        T.id = :id
        $where
        ";
        $data = Application_Model_Global::pquery($sql, array(":id_language"=>$id_language, ":id"=>$id));
        return $data;
    }

    public static function lastId() {
        global $db;
        return $db->lastInsertId();
    }

    public static function updateOrderItem($table_name, $order_item) {
        $sql = "SELECT id, order_item FROM $table_name WHERE order_item>=:order_item";
        $data = Application_Model_Global::pquery($sql, array(":order_item"=>$order_item));

        if (!empty($data)) {
            foreach ($data as $k => $item) {
                $id = $item['id'];
                $where = " id=:id ";
                Application_Model_Global::pupdate($table_name, array('order_item' => $item['order_item'] + 1), $where, array(":id"=>$id));
            } // endforeach     
        } // endif
    }

    public static function updateOrderItemCategory($table_name, $order_item, $id_category_group) {
        $sql = "SELECT id, order_item FROM $table_name WHERE order_item>=:order_item AND id_category_group=:id_category_group";
        $data = Application_Model_Global::pquery($sql, array(":order_item"=>$order_item, ":id_category_group"=>$id_category_group));

        if (!empty($data)) {
            foreach ($data as $k => $item) {
                $id = $item['id'];
                $where = " id=:id ";
                Application_Model_Global::pupdate($table_name, array('order_item' => $item['order_item'] + 1), $where, array(":id"=>$id));
            } // endforeach     
        } // endif
    }

    public static function updateOrderItemImage($table_name, $order_item, $id_item) {
        $sql = "SELECT id, order_item FROM $table_name WHERE id_item=:id_item AND order_item>=:order_item";
        $data = Application_Model_Global::pquery($sql, array(":id_item"=>$id_item, ":order_item"=>$order_item));

        if (!empty($data)) {
            foreach ($data as $k => $item) {
                $id = $item['id'];
                $where = " id=:id ";
                Application_Model_Global::pupdate($table_name, array('order_item' => $item['order_item'] + 1), $where, array(":id"=>$id));
            } // endforeach     
        } // endif
    }

    public static function getMaxOrderItem($table_name) {
        $sql = "SELECT max(order_item) AS max FROM $table_name";
        $data = Application_Model_Global::pqueryRow($sql); 
        return $data['max'];
    }

    public static function getMaxOrderItemCategory($table_name, $id_category_group) {
        $sql = "SELECT max(order_item) AS max FROM $table_name WHERE id_category_group=:id_category_group";
        $data = Application_Model_Global::pquery($sql, array(":id_category_group"=>$id_category_group));
        return $data['max'];
    }

    public static function getMaxOrderItemImage($id_item) {
        $sql = "SELECT max(order_item) AS max FROM " . TABLE_PREFIX . "images_relations WHERE id_item=:id_item";
        $data = Application_Model_Global::pqueryRow($sql, array(":id_item"=>$id_item));
        return $data['max'];
    }

    public static function getByMaxId($table_name, $champs) {
        $sql = "SELECT * FROM $table_name WHERE id = (SELECT MAX($champs) FROM $table_name)";
        $data = Application_Model_Global::pqueryRow($sql);
        return $data;
    }
}
