<?php
class Application_Plugin_LayoutPicker extends Zend_Controller_Plugin_Abstract
{
    public function preDispatch(Zend_Controller_Request_Abstract $request)
    {

        $module = strtolower($request->getModuleName());
        $layout = Zend_Layout::getMvcInstance();


        if ($layout->getMvcEnabled()) {
            $layout->setLayoutPath(APPLICATION_PATH . '/modules/' . $module . '/views/layouts/');
            $layout_name = $module;
            $layout->setLayout($layout_name);
        }
    }
}
