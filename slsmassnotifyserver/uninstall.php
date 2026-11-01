<?php
// SLL Mass Notify Server by the Southland Labs

if (!defined('FREEPBX_IS_AUTH')) {
	die('No direct script access allowed');
}

$freepbx = \FreePBX::Create();
$freepbx->Slsmassnotifyserver->uninstall();
