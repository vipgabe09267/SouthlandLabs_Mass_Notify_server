<?php
declare(strict_types=1);
interface BMO {}
require dirname(__DIR__) . '/slsmassnotifyserver/Slsmassnotifyserver.class.php';

function check_menu($ok, $message) {
    if (!$ok) { throw new RuntimeException($message); }
}
$class = new ReflectionClass(FreePBX\modules\Slsmassnotifyserver::class);
$file = file($class->getFileName());
$methods = '';
foreach (['retireLegacyFrameworkMenu', 'repairUpdateSensitiveIntegration', 'verifyFrameworkMenuRegistration'] as $name) {
    $method = $class->getMethod($name);
    $methods .= implode('', array_slice($file, $method->getStartLine() - 1, $method->getEndLine() - $method->getStartLine() + 1));
}
eval('class FixtureFrameworkMenu {
    public $contents; public $writes = 0; public $widgets = 0;
    function requireRuntimeAccount() {}
    function ensureDashboardWidget() { $this->widgets++; }
    function readManagedTextFile($path, $limit, $readOnly) {
        if (!$readOnly || $path !== "/var/www/html/admin/views/menu_items.php") { throw new LogicException("Unexpected menu read"); }
        return $this->contents;
    }
    function writeManagedTextFile($path, $data, $mode, $limit, $expected) {
        if ($mode !== null) { throw new LogicException("Migration must retain existing file permissions"); }
        if ($this->contents !== $expected) { throw new LogicException("Race guard was missing"); }
        $this->contents = $data; $this->writes++;
    }
' . $methods . '}');
$module = new FixtureFrameworkMenu();
$fixture = json_decode(file_get_contents(__DIR__ . '/fixtures/framework-17.0.33.2-module-sig-excerpt.json'), true, 512, JSON_THROW_ON_ERROR);
$stock = base64_decode($fixture['files_base64']['amp_conf/htdocs/admin/views/menu_items.php'], true);
check_menu(is_string($stock) && hash('sha256', $stock) === '25cd92564fe099d331241defda8a0c4c2a9fb9afc2bd4ac239a4809fb876ffa8', 'Vendor menu renderer fixture does not match its signed digest');
$trust = file_get_contents(dirname(__DIR__) . '/slsmassnotifyserver/bin/sls_mass_notify/sls_upgrade_trust.py');
check_menu(preg_match("/^MENU = b'''(.*?)'''/ms", $trust, $match) === 1, 'Legacy deployment fixture missing');
$block = str_replace('\\t', "\t", $match[1]);
check_menu(hash('sha256', $block) === 'b95a902541a9d115b06ef70ccb9fd7557db5c011d3838ee0f381bdc11987b257', 'Unexpected history fixture');
$anchor = "\telse if (\$a == 'other')\n\t\treturn true;\n";
$old = str_replace($anchor, $block . $anchor, $stock, $insertions);
check_menu($insertions === 1, 'Stock render fixture does not contain the earlier insertion point');
$before = hash('sha256', $old); $after = hash('sha256', $stock);
$module->contents = $old;
$module->retireLegacyFrameworkMenu($before, $after);
$module->retireLegacyFrameworkMenu($before, $after);
$module->repairUpdateSensitiveIntegration();
check_menu($module->contents === $stock && $module->writes === 1 && $module->widgets === 1, 'Legacy upgrade or subsequent maintenance disturbed the vendor menu');
foreach ([
    [$old . "/* local */", $before, $after],
    [$old, $before, str_repeat('0', 64)],
    [str_replace($block, $block . $block, $old), '', $after],
    [str_replace('return -1;', 'return 91;', $old), '', $after],
] as [$input, $approvedBefore, $approvedAfter]) {
    $module->contents = $input;
    try {
        $module->retireLegacyFrameworkMenu($approvedBefore ?: hash('sha256', $input), $approvedAfter);
        throw new LogicException('Unapproved modification was accepted');
    } catch (RuntimeException $expected) {
        check_menu($module->contents === $input && $module->writes === 1, 'Refusal modified the template');
    }
}

// Run the authentic unmodified vendor renderer with module.xml's own navigation data.
class FreePBX {
    static function create() { return (object)['astman' => new class { function connected() { return true; } }]; }
    static function Config() { return new class { function get($name) { return 'database'; } }; }
    static function Modules() {
        return new class { function getInfo($name) { return [$name => ['items' => $GLOBALS['fpbx_menu']]]; } };
    }
}
class modgettext { static function _($label, $module) { return $label; } }
$amp_conf = ['USE_FREEPBX_MENU_CONF' => false];
$display = 'slsmassnotifyserver'; $fpbx_menu = [];
$xml = simplexml_load_file(dirname(__DIR__) . '/slsmassnotifyserver/module.xml', SimpleXMLElement::class, LIBXML_NONET);
check_menu((string)$xml->category === 'Mass Notify', 'Module Admin should use the native Mass Notify category');
foreach ($xml->menuitems->children() as $id => $item) {
    $record = ['module' => ['rawname' => 'slsmassnotifyserver'], 'name' => (string)$item, 'display' => $id];
    foreach ($item->attributes() as $key => $value) { $record[$key] = (string)$value; }
    $fpbx_menu[$id] = $record;
}
ob_start(); eval('?>' . $stock); $html = ob_get_clean();
check_menu(strpos($html, '>Mass Notify</a>') !== false, 'Mass Notify native category missing');
foreach ($fpbx_menu as $item) {
    check_menu(strpos($html, 'href="' . ($item['href'] ?? ('config.php?display=' . $item['display'])) . '"') !== false, 'Native route missing: ' . $item['display']);
}
$module->verifyFrameworkMenuRegistration();
unset($fpbx_menu['slsmassnotifyserver_operations']);
try {
    $module->verifyFrameworkMenuRegistration();
    throw new LogicException('Missing operator portal registration was accepted');
} catch (RuntimeException $expected) {
    check_menu(strpos($expected->getMessage(), 'navigation') !== false, 'Unexpected registration failure');
}
echo "Authenticated legacy migration, stock menu rendering and repair without Framework writes passed.\n";
