<?php
class AjaxController extends Application_AbstractController
{

    public function init()
    {
        // error_reporting(E_ALL);
        // ini_set("display_errors",1);
    }

    /**
     * Generic zend-form ajax validator
     */
    public function validateformAction()
    {
        // error_reporting(E_ALL);
        //           ini_set("display_errors",1);

        $formName = $this->getRequest()->getParam('identifier', null);

        if (!$formName || !is_string($formName)) {
            $this->getHelper('json')->sendJson('form validator error');
        }

        $form_class = 'Application_Form_' . $formName;

        if (!class_exists($form_class)) {
            $this->getHelper('json')->sendJson('form validator error');
        }

        $form = new $form_class();

        $form->isValid($this->_getAllParams());

        $json = array();

        if ($form->getElement('csrf')) {
            $form->getElement('csrf')->initCsrfToken();
            $form->getElement('csrf')->initCsrfValidator();
            $new_csrf_hash = $form->getElement('csrf')->getHash();

            $json['ajax_csrf'] = $new_csrf_hash;
        }

        $json['errors'] = $form->getMessages();
        $this->getHelper('json')->sendJson($json);
    }
}
