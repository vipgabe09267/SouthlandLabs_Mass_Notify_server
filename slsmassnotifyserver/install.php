<?php
// SLL Mass Notify Server by the Southland Labs

if (!defined('FREEPBX_IS_AUTH')) {
	die('No direct script access allowed');
}

// FreePBX invokes the BMO install() method before this legacy hook. Keep all
// integration in that method so native installation runs the phase once.
