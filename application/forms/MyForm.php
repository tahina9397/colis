<?php
class Application_Form_MyForm extends Application_Form_Main
{
	private $_id;

	public function __construct(array $params = array())
	{
		$this->_id = $params['id'];
		parent::__construct();
	}

	/**
	 *
	 * Signin form
	 *
	 */
	public function init()
	{
		$cname = explode('_', get_class());
		$this->preInit(end($cname), true, false);

		// use template file
		$this->setDecorators(
			array(
				array(
					'ViewScript', array(
						'viewScript' => 'forms/MyForm.phtml', "id" => $this->_id
					)
				)
			)
		);

		$digits = new Zend_Validate_Digits(false);
		$digits->setMessage($this->translator->translate("seul les chiffres sont acceptés"));

		$user = Application_Model_Global::pselectRow(TABLE_PREFIX . "users", "*", "id=:id", array(":id" => $this->_id));

		$name =  $this->createElement('text', 'name');
		$name->addValidator('NotEmpty', true)
			->setRequired(true)
			->setAttrib("class", "span8")
			->setValue($user["name"]);
		$name->getValidator('NotEmpty')->setMessage($this->translator->translate("le champ nom est obligatoire"));

		$age =  $this->createElement('text', 'age');
		$age->addValidator('NotEmpty', true)
			->addValidator($digits, true)
			->setRequired(true)
			->setAttrib("class", "span8")
			->setValue($user["age"]);
		$age->getValidator('NotEmpty')->setMessage($this->translator->translate("le champ age est obligatoire"));

		$email =  $this->createElement('text', 'email');
		$email->addValidator('NotEmpty', true)
			->addValidator(new Application_Validate_EmailAddress())
			->setRequired(true)
			->setAttrib("class", "span8")
			->setValue($user["email"]);
		$email->getValidator('NotEmpty')->setMessage($this->translator->translate("le champ email est obligatoire"));

		// // Message
		// $message = new Zend_Form_Element_Textarea('message');
		// $message->addFilter('StripTags')
		// 	->addValidator('NotEmpty', true)
		// 	->setRequired(true)
		// 	->setAttrib('ROWS', "7");
		// $message->getValidator('NotEmpty')->setMessage($this->translator->translate("veuillez laisser un message"));

		// submit button
		$submit = new Zend_Form_Element_Submit('submit');

		$this->addElements(
			array(
				$name,
				$age,
				$email,
				// $message,
				$submit
			)
		);

		$elements = $this->getElements();
		foreach ($elements as $element) {
			$element->removeDecorator('DtDdWrapper')
				->removeDecorator('HtmlTag')
				->removeDecorator('Label');
		}

		$this->addElements(array());
		$this->postInit();
	}
}
