<?php
require_once __DIR__ . '/init.php';
require_once __DIR__ . '/constants.php';

// timezone
date_default_timezone_set("Africa/Nairobi");

try {
	Application::run();
} catch (Exception $e) {
	echo $e->getMessage();
}
