<?php
// SLL Mass Notify Server by the Southland Labs

if (!defined('FREEPBX_IS_AUTH')) {
	die('No direct script access allowed');
}

// FreePBX invokes the BMO uninstall() method after this legacy hook. Keep all
// teardown in that method so native removal runs the phase once.
