<?php
declare(strict_types=1);

$root = dirname(__DIR__);
function ui_source(string $path): string
{
    $value = file_get_contents($path);
    if (!is_string($value)) { throw new RuntimeException('Unable to read ' . $path); }
    return $value;
}
function ui_check(bool $ok, string $message): void
{
    if (!$ok) { throw new RuntimeException($message); }
}

$save = ui_source($root . '/slsmassnotifyserver/views/save_state.js');
ui_check(str_contains($save, 'options.submit') && str_contains($save, 'labelControls'), 'Shared save-state lost scoped submit handling or accessible-name repair.');
$general = ui_source($root . '/slsmassnotifyserver/views/other_settings.php');
ui_check(str_contains($general, 'id="sls-update-action-form"') && str_contains($general, 'form="sls-update-action-form"'), 'Update actions still submit the General Settings form.');
ui_check(str_contains($general, 'Discard unsaved General Settings and continue?') && str_contains($general, 'Install the selected signed release now?'), 'General update actions lack discard/install confirmation.');
ui_check(str_contains($general, 'markGeneralDirty'), 'General structural editors do not report unsaved changes.');
$integrations = ui_source($root . '/slsmassnotifyserver/views/integrations.js');
ui_check(str_contains($integrations, "operation !== 'read'") && str_contains($integrations, 'window.confirm') && str_contains($integrations, 'maximum_access_seconds'), 'Door control lacks a contextual destructive-operation confirmation.');
$weather = ui_source($root . '/slsmassnotifyserver/views/settings.php');
ui_check(str_contains($weather, 'id="sls-weather-settings"') && str_contains($weather, 'id="sls-weather-settings-form"'), 'Weather settings lack a tracked save boundary.');
ui_check(str_contains($weather, 'Remove Weather zone group') && str_contains($weather, 'SlsSaveState.attach'), 'Weather zone removal lacks confirmation or dirty-state protection.');
$lightning = ui_source($root . '/slsmassnotifyserver/views/lightning.php');
ui_check(str_contains($lightning, 'id="sls-lightning-settings"') && str_contains($lightning, 'id="sls-lightning-settings-form"') && str_contains($lightning, 'SlsSaveState.attach'), 'Lightning settings lack dirty-state protection.');
$paging = ui_source($root . '/slsmassnotifyserver/views/paging.php');
ui_check(str_contains($paging, 'SlsSaveState.attach') && str_contains($paging, 'SlsSaveState?.set'), 'Paging structural changes lack dirty-state protection.');
$scheduling = ui_source($root . '/slsmassnotifyserver/views/scheduling.php');
ui_check(str_contains($scheduling, 'id="sls-scheduling"') && str_contains($scheduling, 'SlsSaveState.attach'), 'Scheduling editor lacks dirty-state protection.');
echo "UI safety contract: scoped save boundaries, confirmations, structural dirty state and shared accessible names passed.\n";
