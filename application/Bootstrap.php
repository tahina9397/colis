<?php

class Bootstrap extends Zend_Application_Bootstrap_Bootstrap
{

    protected $_docRoot;
    private $_option;

    protected function _initPath()
    {
        $this->_docRoot = realpath(APPLICATION_PATH . '/../');
        Zend_Registry::set('docRoot', $this->_docRoot);
    }

    protected function _initLoaderResource()
    {
        $resourceLoader = new Zend_Loader_Autoloader_Resource(array(
            'basePath' => $this->_docRoot . '/application',
            'namespace' => 'Application'
        ));

        $resourceLoader->addResourceTypes(array(
            'model' => array(
                'namespace' => 'Model',
                'path' => 'models'
            )
        ));
        $resourceLoader->addResourceTypes(array(
            'forms' => array(
                'namespace' => 'Form',
                'path' => 'forms'
            )
        ));
        $resourceLoader->addResourceTypes(array(
            'class' => array(
                'namespace' => 'Class',
                'path' => 'classes'
            )
        ));
        $resourceLoader->addResourceTypes(array(
            'plugin' => array(
                'namespace' => 'Plugin',
                'path' => 'plugins'
            )
        ));
    }

    protected function _initView()
    {
        $view = new Zend_View();

        $view->addHelperPath(
            APPLICATION_PATH . "/../library/Application/View/Helper",
            "Application_View_Helper"
        );

        $view->addHelperPath(
            APPLICATION_PATH . "/../library/ZendX/JQuery/View/Helper",
            "ZendX_JQuery_View_Helper"
        );

        $view->addHelperPath(
            APPLICATION_PATH . "/../library/Langs/View/Helper",
            "Langs_View_Helper"
        );

        $viewRenderer = Zend_Controller_Action_HelperBroker::getStaticHelper('ViewRenderer');
        $viewRenderer->setView($view);

        return $view;
    }

    protected function _initSetupBaseUrl()
    {
        $this->bootstrap('frontcontroller');
        $controller = Zend_Controller_Front::getInstance();

        // if( !Application_Class_Utils::contains('admin', $_SERVER['REQUEST_URI']) ){
        $lang = Application_Class_Utils::getCurrentLang();
        if ($lang != DEFAULT_LANG_ABBR) {
            $controller->setBaseUrl('/' . $lang);
            Zend_Registry::set("baseUrl", '/' . $lang);
        } else {
            Zend_Registry::set("baseUrl", '');
        }
        // }
    }

    protected function _initRoutes()
    {
        $this->bootstrap('FrontController');
        $this->_frontController = $this->getResource('FrontController');

        $router = $this->_frontController->getRouter();
        $controller = Zend_Controller_Front::getInstance();

        $lang = Application_Class_Utils::getCurrentLang();

        $langRoute = new Zend_Controller_Router_Route(
            ':lang/',
            array(
                'lang' => $lang
            ),
            array(
                'lang' => '[a-z]{0,2}'
            )
        );

        $defaultRoute = new Zend_Controller_Router_Route(
            ':controller/:action/*',
            array(
                'module'     => 'default',
                'controller' => 'index',
                'action'     => 'index'
            )
        );

        $defaultRoute = $langRoute->chain($defaultRoute);

        $router->addRoute('langRoute', $langRoute);
        $router->addRoute('defaultRoute', $defaultRoute);

        $this->_frontController->registerPlugin(new Application_Controller_Plugin_Language());
        // $this->_frontController->registerPlugin(new Application_Controller_Plugin_Compress());
    }

    protected function _initConfig()
    {
        $Options = new Application_Model_Options();

        try {
            $options = $Options->getAllOptions();
        } catch (Zend_Exception $e) {
            echo 'ERROR: Options cannot be loaded. Make sure your database has been imported. If you wish to run installer again please remove config.php file.<br />';
            echo $e->getMessage();
            die;
        }

        $zend_options = array();
        $option = new Zend_Config(array_merge($options, $zend_options), true);

        Zend_Registry::set('option', $option);
        $this->_option = $option;

        return;
    }

    protected function _initAutoload()
    {
        $controller = Zend_Controller_Front::getInstance();

        // load hooks
        $controller->registerPlugin(new Application_Plugin_Hooks());
    }
}
