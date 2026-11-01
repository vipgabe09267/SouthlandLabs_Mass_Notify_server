<?php
declare(strict_types=1);
interface BMO {}
require dirname(__DIR__) . '/slsmassnotifyserver/Slsmassnotifyserver.class.php';
$class = new ReflectionClass(FreePBX\modules\Slsmassnotifyserver::class);
if (!$class->hasMethod('bundledRecordingRowOwned')) {
    throw new RuntimeException('Bundled recording ownership must recognize both publisher labels during a rebrand upgrade.');
}
$method = $class->getMethod('bundledRecordingRowOwned');
$module = $class->newInstanceWithoutConstructor();
$recording = ['name' => 'SLL Mass Notify Server - NWS Alert', 'description' => 'Default Southland Labs NWS alert opening tone.'];
$old = ['displayname' => 'SLS Mass Notify - NWS Alert', 'description' => 'Default Southland Servers NWS alert opening tone.'];
$new = ['displayname' => $recording['name'], 'description' => $recording['description']];
foreach ([$old, $new] as $row) {
    if ($method->invoke($module, $row, $recording) !== true) {
        throw new RuntimeException('An exact old/new bundled recording pair was refused.');
    }
}
foreach ([['displayname' => 'Administrator recording', 'description' => $recording['description']],
    ['displayname' => $recording['name'], 'description' => 'Administrator description'],
    ['displayname' => $old['displayname'], 'description' => $new['description']],
    ['displayname' => $new['displayname'], 'description' => $old['description']], []] as $row) {
    if ($method->invoke($module, $row, $recording) !== false) {
        throw new RuntimeException('Changed or mixed-brand recording labels were treated as publisher-owned.');
    }
}
echo "Recording branding: exact old/new ownership pairs accepted; administrator edits and mixed labels refused.\n";
