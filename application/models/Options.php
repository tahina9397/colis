<?php

class Application_Model_Options extends Zend_Db_Table_Abstract
{
	protected $_name = "colis_options";
	protected $_rowClass = "Application_Model_Options_Row";

	/**
	 * updates option (insert key if not exists)
	 */
	public function updateOption($meta_key, $meta_value)
	{
		$this->delete(array(
			'meta_key = ?' => $meta_key
		));
		
		$result = $this->insert(array(
			'meta_key' => $meta_key,
			'meta_value' => (string) $meta_value
		));
		
		return $result;
	}

	/**
	 * get all options
	 */
	public function getAllOptions()
	{
		return $this->getAdapter()->fetchPairs($this->select());
	}

	/**
	 * remove meta key
	 */
	public function removeMeta($meta_key)
	{
		return $this->delete(array(
			'meta_key = ?' => $meta_key
		));
	}
}

class Application_Model_Options_Row extends Zend_Db_Table_Row_Abstract
{
}