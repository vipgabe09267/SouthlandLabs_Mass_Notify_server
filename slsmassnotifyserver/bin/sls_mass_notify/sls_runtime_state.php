<?php
declare(strict_types=1);
namespace SLS\MassNotify;

/** Admission policy; receipt handling and administration remain available. */
final class RuntimeState
{
    public const LITE_ENTERPRISE_MESSAGE = 'Enterprise Labs is unavailable in Lite mode. Its saved configuration is retained. Use the verified installer with --standard on a PBX that meets Standard requirements to enable Enterprise Labs.';

    public static function enterpriseAvailable(array $settings): bool
    {
        return ($settings['deployment_profile'] ?? 'standard') === 'standard';
    }

    public static function requireEnterpriseAvailable(array $settings): void
    {
        if (!self::enterpriseAvailable($settings)) { throw new \DomainException(self::LITE_ENTERPRISE_MESSAGE); }
    }

    public static function labsEnabled(array $settings): bool
    {
        $value=$settings['enterprise_labs']??[];
        return self::enterpriseAvailable($settings) && is_array($value) && !array_diff(array_keys($value),['enabled']) && ($value['enabled']??false)===true;
    }

    public static function requireLabsEnabled(array $settings): void
    {
        self::requireEnterpriseAvailable($settings);
        if (!self::labsEnabled($settings)) {
            throw new \DomainException('Enterprise Labs is disabled. Enable it in Feature manager before running this operation.');
        }
    }

    public static function running(array $settings): bool
    {
        $value = $settings['runtime_enabled'] ?? true;
        if (array_key_exists('runtime_enabled', $settings) && !is_bool($settings['runtime_enabled'])) {
            throw new \DomainException('SLL runtime_enabled must be a boolean; notification admission is blocked.');
        }
        return $value;
    }

    public static function requireRunning(array $settings): void
    {
        if (!self::running($settings)) { throw new \DomainException('SLL notifications are stopped. Run sudo slsconsole start to resume. No new notification was submitted.'); }
    }
}
