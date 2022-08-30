<?php
class IndexController extends Application_AbstractController
{
	protected $version;

	public function init()
	{
	}

	public function indexAction()
	{
		$this->view->headTitle()->append('Accueil');
		$this->view->inlineScript()->appendFile(THEMES_DEFAULT_URL . 'scripts/index/index.js?v=' . rand(), 'text/javascript');
	}
}
