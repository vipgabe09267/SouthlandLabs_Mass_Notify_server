<?php
declare(strict_types=1);
namespace SLS\MassNotify;
require_once __DIR__ . '/AutomationConfig.php';
require_once __DIR__ . '/AutomationStore.php';
require_once __DIR__ . '/api/sls-mass-notify/security.php';
require_once __DIR__ . '/ConfigCrypto.php';
require_once __DIR__ . '/bin/sls_mass_notify/sls_runtime_state.php';

/** Read-only authorization at an external transmission boundary. */
final class DeliveryAuthorization
{
    public const CONFIG = '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config';

    public static function settings(string $path = self::CONFIG): array
    {
        clearstatcache(true, $path);
        $parent = @lstat(dirname($path));
        if (!$parent || ($parent['mode'] & 0170000) !== 0040000 || realpath(dirname($path)) !== dirname($path)
            || ($parent['mode'] & 0022)) { throw new \RuntimeException('Protected configuration is unavailable.'); }
        return \FreePBX\modules\SlsConfigCrypto::readFile($path);
    }

    public static function parseInput(string $raw): array
    {
        if ($raw === '' || strlen($raw) > 16384) { throw new \InvalidArgumentException('Invalid authorization input.'); }
        return ApiSecurity::jsonObject($raw, false, 12);
    }

    /** Hash only the saved email route and sender fields, before normalization.
     * The caller binds this raw projection to its validated settings snapshot.
     * Unrelated settings writes, including MFA counters, do not change it.
     */
    public static function emailTargetHash(array $settings, string $id): string
    {
        if (!preg_match('/^email_[a-f0-9]{24}$/D', $id)) { return ''; }
        $email = $settings['announcement_email'] ?? null;
        if (!is_array($email) || !in_array($email['enabled'] ?? '0', ['1', 1, true], true)
            || !is_array($email['recipients'] ?? null) || !array_is_list($email['recipients']) || count($email['recipients']) > 50) { return ''; }
        $selected = [];
        foreach ($email['recipients'] as $row) {
            if (is_array($row) && ($row['id'] ?? null) === $id) { $selected[] = $row; }
        }
        if (count($selected) !== 1 || !in_array($selected[0]['enabled'] ?? '1', ['1', 1, true], true)) { return ''; }
        $sender = [];
        foreach (['mail_from_name', 'mail_from_domain', 'mail_from_local_part', 'mail_from_addr'] as $key) {
            $sender[$key] = [array_key_exists($key, $settings), $settings[$key] ?? null];
        }
        return hash('sha256', json_encode([$email['enabled'], $selected[0], $sender], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    /** Email has a separate strict input contract; permits() remains webhook-only. */
    public static function permitsEmail(array $settings, array $input, string $journal = AutomationStore::DIRECTORY, ?int $now = null, ?int &$validUntil = null): bool
    {
        $validUntil = null;
        $liveClock = $now === null;
        $now ??= time();
        if (array_diff(array_keys($input), ['recipient_id', 'target_hashes', 'expires_at', 'schedule_deadline', 'api_credential_id', 'api_credential_revision', 'automation_context'])
            || !is_string($input['recipient_id'] ?? null) || !is_array($input['target_hashes'] ?? null)
            || !array_is_list($input['target_hashes']) || !$input['target_hashes'] || count($input['target_hashes']) > 3
            || !is_int($input['expires_at'] ?? null) || $input['expires_at'] <= $now
            || !array_key_exists('schedule_deadline', $input)
            || ($input['schedule_deadline'] !== null && (!is_int($input['schedule_deadline']) || $input['schedule_deadline'] <= $now))
            || !RuntimeState::running($settings)) { return false; }
        $seen=[];
        foreach($input['target_hashes']as$hash){
            if(!is_string($hash)||!preg_match('/^[a-f0-9]{64}$/D',$hash)||isset($seen[$hash])){return false;}
            $seen[$hash]=true;
        }
        $current = self::emailTargetHash($settings, $input['recipient_id']);
        if ($current === '' || !isset($seen[$current])) { return false; }
        $deadline = min($input['expires_at'], $input['schedule_deadline'] ?? $input['expires_at']);
        if (array_key_exists('automation_context', $input)) {
            $context = $input['automation_context'];
            if (!is_array($context) || !is_dir($journal) || !(new AutomationStore($journal))->permits($context, $now)) { return false; }
            $allowed = self::automationChannelIds($settings, $context, $now, 'email_recipient_ids');
            if ($allowed === null || !in_array($input['recipient_id'], $allowed, true)) { return false; }
            $deadline = min($deadline, $context['expires_at']);
        }
        // Source readers may wait; check the principal after those reads.
        $principal = null;
        if (array_key_exists('api_credential_id', $input)) {
            $revision = $input['api_credential_revision'] ?? null;
            if (!is_string($input['api_credential_id']) || ($revision !== null
                && (!is_string($revision) || !preg_match('/^[a-f0-9]{64}$/D', $revision)))) { return false; }
            $principal = ApiSecurity::currentCredential($settings, $input['api_credential_id'], $revision);
            if (!$principal || !ApiSecurity::permitsResolvedAnnouncement($principal, ['email_recipient_ids'=>[$input['recipient_id']]], $settings)) { return false; }
            if (($principal['expires_at'] ?? 0) > 0) { $deadline = min($deadline, $principal['expires_at']); }
        }
        $checkedAt = $liveClock ? time() : $now;
        if ($deadline <= $checkedAt || ($principal !== null && !ApiSecurity::credentialActive($principal, $checkedAt))) { return false; }
        $validUntil = $deadline;
        return true;
    }

    /** Return the webhook audience frozen by the current automation template. */
    private static function automationWebhookIds(array $settings, array $context, int $now): ?array
    {
        return self::automationChannelIds($settings, $context, $now, 'webhook_ids');
    }

    private static function automationChannelIds(array $settings, array $context, int $now, string $field): ?array
    {
        try {
            $resolved = AutomationConfig::resolvePermitted($settings, $context, $now);
            if ($resolved === null) { return null; }
            if (!is_array($resolved['template'] ?? null)) { return []; }
            $delivery = IncidentConfig::delivery($resolved['template']['delivery'] ?? []);
        } catch (\Throwable $error) { return null; }
        $allowed = $delivery[$field];
        if (!$delivery['group_ids']) { return $allowed; }
        $groups = [];
        $savedGroups = $settings['announcement_groups'] ?? [];
        if (!is_array($savedGroups) || !array_is_list($savedGroups)) { return null; }
        foreach ($savedGroups as $group) {
            if (!is_array($group) || !is_string($group['id'] ?? null) || isset($groups[$group['id']])) { return null; }
            $groups[$group['id']] = $group;
        }
        foreach ($delivery['group_ids'] as $groupId) {
            $group = $groups[$groupId] ?? null;
            $ids = is_array($group) ? ($group[$field] ?? []) : null;
            if (!is_array($ids) || !array_is_list($ids)) { return null; }
            foreach ($ids as $id) {
                if (!is_string($id) || !preg_match($field === 'email_recipient_ids' ? '/^email_[a-f0-9]{24}$/D' : '/^[A-Za-z0-9_-]{1,64}$/D', $id)) { return null; }
                $allowed[] = $id;
            }
        }
        return array_values(array_unique($allowed));
    }

    public static function permits(array $settings, array $input, string $journal = AutomationStore::DIRECTORY, ?int $now = null): bool
    {
        $now ??= time();
        if (array_diff(array_keys($input), ['automation_context', 'api_credential_id', 'api_credential_revision', 'webhook_ids'])
            || (!array_key_exists('automation_context', $input) && !array_key_exists('api_credential_id', $input))
            || !RuntimeState::running($settings)) { return false; }
        $ids = $input['webhook_ids'] ?? null;
        if (!is_array($ids) || !array_is_list($ids) || !$ids || count($ids) > 10) { return false; }
        $seen=[];
        foreach ($ids as $id) {
            if (!is_string($id) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $id) || isset($seen[$id])) { return false; }
            $seen[$id]=true;
        }
        if (array_key_exists('automation_context', $input)) {
            $context = $input['automation_context'];
            if (!is_array($context) || !is_dir($journal) || !(new AutomationStore($journal))->permits($context, $now)) { return false; }
            $allowed = self::automationWebhookIds($settings, $context, $now);
            if ($allowed === null || array_diff($ids, $allowed)) { return false; }
        }
        if (array_key_exists('api_credential_id', $input)) {
            $revision = $input['api_credential_revision'] ?? null;
            if (!is_string($input['api_credential_id']) || ($revision !== null
                && (!is_string($revision) || !preg_match('/^[a-f0-9]{64}$/D', $revision)))) { return false; }
            $principal = ApiSecurity::currentCredential($settings, $input['api_credential_id'], $revision);
            if (!$principal || !ApiSecurity::permits($principal, 'send')) { return false; }
            if (($principal['audience']['unrestricted'] ?? false) !== true
                && array_diff($ids, ApiSecurity::allowedAudience($principal, $settings)['webhooks'])) { return false; }
        }
        return true;
    }
}
