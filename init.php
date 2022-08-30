<?php
// show/hide errors
// error_reporting(E_ALL);
// ini_set("display_errors", 1);

error_reporting(0);
ini_set("display_errors", 0);

// UTC
date_default_timezone_set('UTC');

// define root path
defined('ROOT_PATH')
	|| define('ROOT_PATH', __DIR__);

// define path to application directory
defined('APPLICATION_PATH')
	|| define('APPLICATION_PATH', __DIR__ . '/application');


// define application environment
defined('APPLICATION_ENV')
	|| define('APPLICATION_ENV', (getenv('APPLICATION_ENV') ? getenv('APPLICATION_ENV') : 'production'));

// set include path
set_include_path(realpath(APPLICATION_PATH . '/../library')
	. PATH_SEPARATOR . get_include_path()
	. PATH_SEPARATOR . APPLICATION_PATH . '/layouts/scripts'
	. PATH_SEPARATOR . APPLICATION_PATH . '/public/ckeditor');

// zend required files
require_once 'Zend/Config/Ini.php';
require_once 'Zend/Application.php';
require_once 'Zend/Session.php';

// load composer library
require_once ROOT_PATH . '/vendor/autoload.php';

// database config
require_once APPLICATION_PATH . '/configs/db.php';

// session start
Zend_Session::start();

class Application
{
	public static $env;
	public static $params = array();
	public static $db;
	public static $siteconfig = array();
	public static $db_adapter = array();
	public static $db_config = array();

	public static function bootstrap($resource = null)
	{
		include_once 'Zend/Loader/Autoloader.php';
		$autoloader = Zend_Loader_Autoloader::getInstance();
		$autoloader->registerNamespace('Application_');
		$application = new Zend_Application(self::_getEnv(), self::_getConfig(), self::_setDb(), self::_setDbTranslationSiteConfig(), self::_setParams(), self::_setCKEditor(), self::_setDirToTranslate());
		return $application->getBootstrap()->bootstrap($resource);
	}

	public static function run()
	{
		self::bootstrap()->run();
	}

	private static function _getEnv()
	{
		return self::$env ?: APPLICATION_ENV;
	}

	private static function _getConfig()
	{
		$env = self::_getEnv();
		$config = new Zend_Config_Ini(APPLICATION_PATH . '/configs/application.ini', $env, true);
		return $config->toArray();
	}

	private static function _setDb()
	{
		$db_adapter = array(
			'adapter' => 'PDO_MYSQL',
			'params' => array(
				'host'     => DB_HOST,
				'dbname'   => DB_DATABASENAME,
				'username' => DB_USERNAME,
				'password' => DB_PASSOWRD,
				'charset'  => 'utf8'
			)
		);

		self::$db_adapter = $db_adapter;
		self::$db_config = new Zend_Config($db_adapter);
	}

	private static function _setDbTranslationSiteConfig()
	{
		// save db configs on registry
		global $db;
		$db = Zend_Db::factory(self::$db_config);
		Zend_Db_Table::setDefaultAdapter($db);
		Zend_Registry::set('db', $db);
		$db->query('SET NAMES utf8mb4');
		self::$db = $db;

		// zend translation
		$data = array(
			'dbAdapter'    => $db, 'tableName'   => TABLE_PREFIX . 'translations_multilingual', 'localeField' => 'language_abbreviation', 'keyField'    => 'key', 'valueField'  => 'value'
		);

		$options = array();

		try {
			$translate = new Zend_Translate('Langs_Translate_Adapter_Db', $data, "fr", $options);
			$translate->addTranslation($data, 'en', $options);
			$translate->setLocale("fr");

			// Set this Translation as global translation for the view helper
			$t = Zend_Registry::set('Zend_Translate', $translate);
		} catch (Zend_Translate_Exception $zte) {
			echo '<h1>' . $zte->getMessage() . '</h1>' . PHP_EOL;
		}
	}

	private static function _setParams()
	{
		$env = self::_getEnv();
		$config = new Zend_Config_Ini(APPLICATION_PATH . '/configs/application.ini', $env, true);

		// save params configs on registry
		Zend_Registry::set('params', $config->params);

		global $settings;
		Zend_Registry::set('settings', $settings);

		global $version;
		Zend_Registry::set('version', rand());
	}

	private static function _setCKEditor()
	{
		require_once CKEDITOR_PATH . 'ckeditor.php';
		global $CKEditor;
		$CKEditor = new CKEditor();
	}

	private static function _setDirToTranslate()
	{
		// need when scan translations in php files
		global $dirs_to_translate;
		$dirs_to_translate = array();
		Zend_Registry::set('dirs_to_translate', $dirs_to_translate);
	}
}
