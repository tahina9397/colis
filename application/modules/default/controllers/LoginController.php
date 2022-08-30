<?php

class LoginController extends Application_AbstractController
{
    public function init()
    {
        $this->version = $version = Zend_Registry::get('version');
        $this->_helper->layout->setLayout('login');

        $ajaxContext = $this->_helper->getHelper('AjaxContext');
        $ajaxContext->initContext();

        $User = new Application_Model_User("admin");
        $storage = $User->getStorage();

        if (!$storage->isEmpty()) {
            $this->_redirect($this->view->baseUrl() . '/');
        }
    }

    public function indexAction()
    {
        $this->view->headTitle()->append($this->view->translate("Se connecter"));

        $signinForm = new Application_Form_Signin();
        $this->view->signinForm = $signinForm;
    }

    public function authenticateAction()
    {
        $this->_helper->layout->disableLayout();
        $this->_helper->viewRenderer->setNoRender();

        $ret = array();

        $email = trim($this->_getParam('email'));
        $password = trim($this->_getParam('password'));
        $rememberme = (int)$this->_getParam('rem', 0);

        if ($email && $password) {
            // brute force hack
            // bloque l'IP 15 min si
            // les 3 derniers mots de passes rentrés les 5 dernières min sont erronés
            $loginStatus = Application_Model_User::getLoginStatus(TABLE_PREFIX . "users_login", "ip", $_SERVER['REMOTE_ADDR']);
            if ($loginStatus['status'] == "delay") {
                $ret['state'] = 'error';
                $ret['msg'] = str_replace("#delai#", $loginStatus['message'], $this->view->translate("Votre IP est bloqué. Veuillez réessayer dans #delai# minutes."));;
            } else {
                $w = "email = :email";
                $sql = "SELECT id,password,status FROM " . TABLE_PREFIX . "users WHERE $w";
                $get = Application_Model_Global::pqueryRow($sql, array(":email" => $email));

                $Hash = new Application_Class_Hash();
                if ($Hash->check($password, $get['password'])) {
                    if (!$get["status"]) {
                        $ret['state'] = 'error';
                        $ret['msg'] = $this->view->translate("Compte inactif");
                    } else {
                        // bool setcookie ( string $name [, string $value [, int $expire = 0 [, string $path [, string $domain [, bool $secure = false [, bool $httponly = false ]]]]]] )
                        if ($rememberme == 1) :
                            setcookie("email", $email, time() + 60 * 60 * 24 * 100, "/", Zend_Registry::get('params')->cookie_domain);
                            setcookie("password", $password, time() + 60 * 60 * 24 * 100, "/", Zend_Registry::get('params')->cookie_domain);
                            setcookie("rememberme", 1, time() + 60 * 60 * 24 * 100, "/", Zend_Registry::get('params')->cookie_domain);
                        else :
                            setcookie("email", "", NULL, "/", Zend_Registry::get('params')->cookie_domain);
                            setcookie("password", "", NULL, "/", Zend_Registry::get('params')->cookie_domain);
                            setcookie("rememberme", 0, time() + 60 * 60 * 24 * 100, "/", Zend_Registry::get('params')->cookie_domain);
                        endif;

                        Zend_Loader::loadClass('Zend_Auth_Adapter_DbTable');
                        $dbAdapter   = Zend_Registry::get('db');
                        $authAdapter = new Zend_Auth_Adapter_DbTable($dbAdapter);
                        $authAdapter->setTableName(TABLE_PREFIX . 'users')
                            ->setIdentityColumn('email')
                            ->setCredentialColumn('password');
                        $authAdapter->setIdentity($email);
                        $authAdapter->setCredential($get['password']);

                        $auth = Zend_Auth::getInstance();
                        $result = $auth->authenticate($authAdapter);

                        if ($result->isValid()) {
                            $data = $authAdapter->getResultRowObject(null, 'password');
                            $id_type_user = (int)$data->id_type_user;
                            $type_user = Application_Model_Global::pselectRow(TABLE_PREFIX . "type_users", "id,privilege", "id=:id", array(":id" => $id_type_user));
                            $data->privilege = $type_user['privilege'];

                            $auth->setStorage(new Zend_Auth_Storage_Session('admin'));
                            $auth->getStorage()->write($data);

                            // update last
                            $id = $data->id;
                            Application_Model_Global::pupdate(TABLE_PREFIX . "users", array('last_activity' => date('Y-m-d H:i:s'), 'online' => '1'), "id = :id", array(":id" => $id));
                            Application_Model_Global::insert(TABLE_PREFIX . "users_logs_connexion", array('id_user' => $id, 'ip' => $_SERVER['REMOTE_ADDR'], 'login_time' => date('Y-m-d H:i:s')));
                            $ret['state'] = 'success';
                            $ret['msg'] = $this->view->translate("Login avec succès");
                        } else {
                            $ret['state'] = 'error';
                            $ret['msg'] = $this->view->translate("Email et/ou mot de passe incorrecte");
                        }
                    }
                } else {
                    $data = array(
                        'id_user' => $get["id"], 'ip' => $_SERVER['REMOTE_ADDR'], 'attempted_at' => Application_Plugin_Common::now()
                    );
                    Application_Model_Global::insert(TABLE_PREFIX . "users_login", $data);
                    $ret['state'] = 'error';
                    $ret['msg'] = $this->view->translate("Email et/ou mot de passe incorrecte");
                }
            }
        }
        echo Zend_Json::encode($ret);
    }

    public function passwordrecoveryAction()
    {
        $this->view->headTitle()->append('Mot de passe oublié');

        $signinForm = new Application_Form_Signin();
        $this->view->signinForm = $signinForm;
    }
}
