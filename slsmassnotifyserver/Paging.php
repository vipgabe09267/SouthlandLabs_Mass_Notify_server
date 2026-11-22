<?php
namespace FreePBX\modules;

require_once __DIR__ . '/bin/sls_mass_notify/sls_live_paging.php';

use SLS\MassNotify\LivePagingConfig;

/** Raised only after a successful native inventory query proves a saved object absent. */
final class SlsDeletedPbxObjectException extends \InvalidArgumentException {}

/** A verified prompt cannot be rendered or supplied at this time. */
final class SlsPagingPromptUnavailableException extends \RuntimeException
{
    private string $capacityDetails = '';

    public static function fromCapacityReport(string $report): self
    {
        // Only public filesystem counters and a bounded role can reach the
        // administrator or the FreePBX log. Never copy renderer output wholesale.
        preg_match_all('/\b(?:available_bytes|required_bytes|reserve_bytes|reserved_bytes|requested_bytes|used_bytes|limit_bytes|file_count|limit_files|available_inodes|required_inodes|outstanding_reservations|read_only|kernel_errno)=[0-9]{1,22}\b|\brole=(?:data|temporary|web|destination)\b/',
            substr($report, 0, 512), $fields);
        $details = implode(' ', array_unique($fields[0]));
        $error = new self(trim(_('Insufficient capacity to prepare the paging prompt.') . ' ' . $details));
        $error->capacityDetails = $details;
        return $error;
    }

    public function capacityDetails(): string { return $this->capacityDetails; }
}

/** Internal dial-in live paging; activation uses native FreePBX Apply Config. */
trait SlsLivePaging
{
    private array $pbxReloadWarnings = [];

    private function warnDeletedPbxObjectDuringReload(string $integration): void
    {
        if (isset($this->pbxReloadWarnings[$integration])) { return; }
        $messages = [
            'pending' => _('SLL Mass Notify Server: staged SLL settings were not activated because a selected PBX extension or IVR was removed. Active SLL settings and staged changes were preserved. Review and re-save the SLL Paging or Triggers selections, then use Apply Config again. FreePBX reload continues.'),
            'paging' => _('SLL Mass Notify Server: the SLL paging menu was omitted because a selected PBX extension or IVR was removed. Saved settings were preserved. Review and re-save the SLL Paging selections, then use Apply Config again. FreePBX reload continues.'),
            'panic' => _('SLL Mass Notify Server: an SLL panic shortcut was omitted because a selected caller extension was removed. Saved settings were preserved. Review and re-save that SLL Trigger selection, then use Apply Config again. FreePBX reload continues.'),
        ];
        if (!isset($messages[$integration])) { throw new \LogicException('Unknown SLL reload integration.'); }
        $this->pbxReloadWarnings[$integration] = true;
        // Logging is observational: no fault email, and a failing log handler
        // must not turn a safely omitted SLL route into a failed PBX reload.
        try { @error_log($messages[$integration]); } catch (\Throwable $error) {}
    }

    private function warnPagingPromptsDuringReload(bool $pending, SlsPagingPromptUnavailableException $error): void
    {
        $key = $pending ? 'pending-media' : 'active-media';
        if (isset($this->pbxReloadWarnings[$key])) { return; }
        $this->pbxReloadWarnings[$key] = true;
        $message = $pending
            ? _('SLL Mass Notify Server: a staged paging or panic prompt is unavailable. The staged settings were preserved. Active settings remain in use. Retry Apply Config when speech and storage are available.')
            : _('SLL Mass Notify Server: an active paging or panic route was omitted because its prompt is unavailable. Other playable routes remain available. Retry Apply Config when speech and storage are available.');
        if ($error->capacityDetails() !== '') { $message .= ' ' . $error->capacityDetails(); }
        try { @error_log($message); } catch (\Throwable $error) {}
    }

    /** Private witness for legacy audiences removed by inventory normalization. */
    private function rawSettingsForPbxReload(?array $settings, bool $pending): array
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $activePath = null; $pendingPath = null;
            foreach ([self::SETTINGS_JSON, self::LEGACY_SETTINGS_JSON, self::LEGACY_OLD_SETTINGS_JSON] as $candidate) {
                if ($this->configurationPathMetadata($candidate) !== null) { $activePath = $candidate; break; }
            }
            if ($pending) {
                foreach ([self::PENDING_SETTINGS_JSON, self::LEGACY_PENDING_SETTINGS_JSON, self::LEGACY_OLD_PENDING_SETTINGS_JSON] as $candidate) {
                    if ($this->configurationPathMetadata($candidate) !== null) { $pendingPath = $candidate; break; }
                }
            }
            if ($activePath === null || ($pending && $pendingPath === null)) {
                throw new \RuntimeException(_('The protected SLL configuration changed during reload. Try Apply Config again.'));
            }
            $before = [$this->settingsCacheFingerprint(self::SETTINGS_JSON), $this->settingsCacheFingerprint(self::PENDING_SETTINGS_JSON),
                $this->settingsFileFingerprint($activePath), $pending ? $this->settingsFileFingerprint($pendingPath) : null];
            if (!preg_match('/^[a-f0-9]{64}$/D', $before[2]) || ($pending && !preg_match('/^[a-f0-9]{64}$/D', $before[3]))) {
                throw new \RuntimeException(_('The protected SLL configuration could not be verified during reload.'));
            }
            $activeRaw = $this->loadSettingsFile($activePath);
            $active = $settings === null ? null : $this->normalizeSettings($activeRaw, $activeRaw);
            $raw = $activeRaw; $normalized = $active;
            if ($pending) {
                $pendingRaw = $this->loadSettingsFile($pendingPath);
                $normalized = $settings === null ? null : \SLS\MassNotify\ImmediateSettings::reconcile($active, $this->normalizeSettings($pendingRaw, $pendingRaw));
                $raw = \SLS\MassNotify\ImmediateSettings::reconcile($activeRaw, $pendingRaw);
            }
            $after = [$this->settingsCacheFingerprint(self::SETTINGS_JSON), $this->settingsCacheFingerprint(self::PENDING_SETTINGS_JSON),
                $this->settingsFileFingerprint($activePath), $pending ? $this->settingsFileFingerprint($pendingPath) : null];
            if ($before === $after && ($settings === null || $normalized === $settings)) { return $raw; }
        }
        throw new \RuntimeException(_('The protected SLL configuration changed during reload. Try Apply Config again.'));
    }

    private function reloadHasLegacyPagingGroups(array $settings): bool
    {
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        return $paging['enabled'] === '1' && (bool)array_filter($paging['groups'], static fn($row) => !LivePagingConfig::isStandalone($row));
    }

    private function validatePbxReloadReferences(array $settings, array $rawSettings): void
    {
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        $deleted = null;
        if ($paging['enabled'] === '1') {
            try { $this->validateLivePagingSelection($paging, $settings, $rawSettings); }
            catch (SlsDeletedPbxObjectException $error) { $deleted = $error; }
        }
        if (method_exists($this, 'getPanicExtensionUsage') && $this->getPanicExtensionUsage(true, $settings)) {
            try { $this->validatePanicExtensions($settings); }
            catch (SlsDeletedPbxObjectException $error) { $deleted = $error; }
        }
        if ($deleted !== null) { throw $deleted; }
    }

    private function hasPbxPhoneRoutes(array $settings): bool
    {
        return LivePagingConfig::normalize((array)($settings['live_paging'] ?? []))['enabled'] === '1'
            || (bool)$this->getPanicExtensionUsage(true, $settings);
    }

    /** False means native media admission failed. Keep only playable active caches on this pass. */
    private function applyStagedSettingsForPbxReload(bool $dialplanHook): bool
    {
        if (PHP_SAPI === 'cli' && getenv('SLS_MASS_NOTIFY_PRESERVE_PENDING') === '1') {
            $this->requireRuntimeAccount();
            return true;
        }
        if ($this->getPendingSettings() === null) { return true; }
        try {
            $this->applyPendingSettingsTransaction(true, $dialplanHook);
        } catch (SlsDeletedPbxObjectException $error) {
            $this->warnDeletedPbxObjectDuringReload('pending');
        } catch (SlsPagingPromptUnavailableException $error) {
            $this->warnPagingPromptsDuringReload(true, $error);
            return false;
        } catch (\Throwable $error) {
            throw new \RuntimeException(_('Unable to apply settings.'), 0, $error);
        }
        return true;
    }

    private function normalizeLivePagingSettings($value)
    {
        if (!is_array($value)) { throw new \InvalidArgumentException(_('Live paging settings must be an object.')); }
        return LivePagingConfig::normalize($value);
    }

    private function validateLivePagingFields($value)
    {
        try { $this->normalizeLivePagingSettings($value); return []; }
        catch (\Throwable $error) { return [$error->getMessage()]; }
    }

    public function generateLivePagingPin($length)
    {
        try {
            if (!is_int($length) && (!is_string($length) || !preg_match('/^[4-8]$/D', $length))) {
                throw new \InvalidArgumentException(_('Choose a PIN length between 4 and 8 digits.'));
            }
            return ['success' => true, 'pin' => LivePagingConfig::generatePin((int)$length)];
        } catch (\Throwable $error) { return ['success' => false, 'message' => $error->getMessage()]; }
    }

    private function livePagingInteger($value)
    {
        if (!is_int($value) && (!is_string($value) || !preg_match('/^[0-9]{1,4}$/D', $value))) {
            throw new \InvalidArgumentException(_('Paging numeric settings must contain whole numbers.'));
        }
        return (int)$value;
    }

    public function saveLivePagingSettings(array $input, ?string $revision = null)
    {
        if (!$this->isSetupComplete($this->getActiveSettings())) {
            return ['success' => false, 'message' => $this->getSetupRequiredMessage(), 'errors' => []];
        }
        try {
            $settings = $this->getPendingSettings() ?? $this->getActiveSettings();
            $previous = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
            if ($revision !== null && !hash_equals(hash('sha256', json_encode([$previous, $settings['announcement_groups'] ?? []], JSON_THROW_ON_ERROR)), $revision)) {
                throw new \InvalidArgumentException(_('Paging settings or linked recipients changed while this page was open. Reload Paging and review your changes again.'));
            }
            $previousGroups = array_column($previous['groups'], null, 'group_id');
            if (array_diff(array_keys($input), array_merge(array_keys(LivePagingConfig::defaults()), ['external_access']))) {
                throw new \InvalidArgumentException(_('Unknown live paging form field.'));
            }
            $next = array_replace(LivePagingConfig::defaults(), $input);
            $next['enabled'] = LivePagingConfig::flag($next['enabled']);
            $next['voicemail_enabled'] = LivePagingConfig::flag($input['voicemail_enabled'] ?? $previous['voicemail_enabled'] ?? '1');
            $next['max_duration_seconds'] = $this->livePagingInteger($next['max_duration_seconds']);
            // Large recipient selectors travel as bounded JSON fields so PHP's
            // max_input_vars cannot silently discard any configured recipient.
            if (is_string($next['allowed_callers'])) {
                if (strlen($next['allowed_callers']) > 25000) { throw new \InvalidArgumentException(_('The paging caller selection is too large.')); }
                try { $decoded = json_decode($next['allowed_callers'], false, 4, JSON_THROW_ON_ERROR); }
                catch (\JsonException $error) { throw new \InvalidArgumentException(_('The paging caller selection is invalid.')); }
                if (!is_array($decoded)) { throw new \InvalidArgumentException(_('The paging caller selection must be a list.')); }
                $next['allowed_callers'] = $decoded;
            }
            if (is_string($next['groups'])) {
                if (strlen($next['groups']) > 800000) { throw new \InvalidArgumentException(_('The paging group selection is too large.')); }
                try { $decoded = json_decode($next['groups'], false, 8, JSON_THROW_ON_ERROR); }
                catch (\JsonException $error) { throw new \InvalidArgumentException(_('The paging group selection is invalid.')); }
                if (!is_array($decoded)) { throw new \InvalidArgumentException(_('Paging groups must be a list.')); }
                $next['groups'] = [];
                foreach ($decoded as $row) {
                    if (!$row instanceof \stdClass) { throw new \InvalidArgumentException(_('Each paging group must be an object.')); }
                    $next['groups'][] = (array)$row;
                }
            }
            if (!is_array($next['groups']) || !array_is_list($next['groups']) || count($next['groups']) > 10) {
                throw new \InvalidArgumentException(_('Select no more than 10 live paging groups.'));
            }
            $rows = [];
            foreach ($next['groups'] as $row) {
                if (!is_array($row) || array_diff(array_keys($row), ['group_id', 'menu_number', 'require_pin', 'pin_length', 'pin',
                    'name', 'extensions', 'notify_extensions', 'allowed_callers', 'text_message', 'allow_external', 'external_callers'])) {
                    throw new \InvalidArgumentException(_('Invalid live paging group form field.'));
                }
                $groupId = $row['group_id'] ?? '';
                if (!is_string($groupId)) { throw new \InvalidArgumentException(_('Invalid paging group identifier.')); }
                if ($groupId === '' && LivePagingConfig::isStandalone($row)) { $groupId = 'paging_' . bin2hex(random_bytes(12)); }
                $saved = $previousGroups[$groupId] ?? [];
                // A standalone group cannot silently revert to an announcement
                // reference through an incomplete or truncated form submission.
                if (LivePagingConfig::isStandalone($saved) && !LivePagingConfig::isStandalone($row)) {
                    throw new \InvalidArgumentException(_('The saved paging group is missing its independent group fields.'));
                }
                $length = $this->livePagingInteger($row['pin_length'] ?? 4);
                $pin = $row['pin'] ?? '';
                if (!is_string($pin)) { throw new \InvalidArgumentException(_('Paging PINs must contain digits.')); }
                $hash = (string)($saved['pin_hash'] ?? '');
                if ($pin !== '') {
                    if (!preg_match('/^[0-9]{4,8}$/D', $pin) || strlen($pin) !== $length) {
                        throw new \InvalidArgumentException(_('A paging PIN must match the selected 4–8 digit length.'));
                    }
                    $generatedHash = password_hash($pin, PASSWORD_DEFAULT);
                    if (!is_string($generatedHash) || $generatedHash === '') {
                        throw new \RuntimeException(_('The paging PIN could not be secured. Check PHP password support and retry.'));
                    }
                    $hash = $generatedHash;
                    if (function_exists('sodium_memzero')) { sodium_memzero($pin); } else { $pin = ''; }
                } elseif ($hash !== '' && $length !== (int)($saved['pin_length'] ?? 4)) {
                    throw new \InvalidArgumentException(_('Randomize or enter a new PIN when changing its length.'));
                }
                $normalizedRow = ['group_id' => $groupId, 'menu_number' => $this->livePagingInteger($row['menu_number'] ?? 0),
                    'require_pin' => LivePagingConfig::flag($row['require_pin'] ?? '1'), 'pin_length' => $length, 'pin_hash' => $hash];
                foreach (['name', 'extensions', 'notify_extensions', 'allowed_callers', 'text_message', 'allow_external', 'external_callers'] as $field) {
                    if (array_key_exists($field, $row)) { $normalizedRow[$field] = $row[$field]; }
                }
                $rows[] = $normalizedRow;
            }
            $next['groups'] = $rows;
            $next = LivePagingConfig::normalize($next);
            // Explicitly saving an independent-only menu retires its unused
            // legacy caller list. Loading installed settings never migrates it.
            if (!array_filter($next['groups'], static function (array $row): bool { return !LivePagingConfig::isStandalone($row); })) {
                $next['allowed_callers'] = [];
            }
            $this->validateLivePagingSelection($next, $settings);
            if ($next['enabled'] === '1') { $this->assertLivePagingExtensionAvailable($next['extension']); }
            $settings['live_paging'] = $next;
            $this->persistPendingSettings($this->normalizeSettings($settings));
            return ['success' => true, 'message' => $next['enabled'] === '1'
                ? _('Paging settings saved. Use Apply Config to prepare the spoken prompts and activate the menu.')
                : _('Paging settings saved, but dial-in paging is disabled. Enable it and use Apply Config before dialing.'), 'errors' => []];
        } catch (\InvalidArgumentException $error) {
            return ['success' => false, 'message' => _('Live paging settings were not saved.'), 'errors' => [$error->getMessage()]];
        } catch (\Throwable $error) {
            // Never log POST bodies, entered PINs, hashes, or the protected file.
            return ['success' => false, 'message' => _('Live paging settings were not saved.'),
                'errors' => [_('The protected configuration or extension availability check failed. Check PBX health and try again.')]];
        }
    }

    private function validateLivePagingSelection(array $paging, array $settings, ?array $rawSettings = null)
    {
        $legacy = array_filter($paging['groups'], static fn($row) => !LivePagingConfig::isStandalone($row));
        $rawTargets = [];
        // Validate the entire selected raw source before classifying any native
        // deletion; an early removed ID must not hide later malformed data.
        if ($rawSettings !== null && $legacy) {
            $groups = $rawSettings['announcement_groups'] ?? [];
            if (!is_array($groups) || $this->validateAnnouncementGroupFields($groups)) {
                throw new \InvalidArgumentException(_('The saved legacy paging audiences are malformed. Review the saved groups.'));
            }
            $groups = array_column($groups, null, 'id');
            foreach ($legacy as $row) {
                $targets = $groups[$row['group_id']]['extensions'] ?? null;
                if (!is_array($targets) || !$targets) {
                    throw new \InvalidArgumentException(_('A selected legacy paging group is missing or has no saved phone audience. Review the paging menu.'));
                }
                $rawTargets[$row['group_id']] = $targets;
            }
        }
        $deletedMessage = null;
        if ($paging['enabled'] === '1' && ($paging['external_access'] ?? '0') === '1') {
            if (!$paging['external_ivr_ids']) { throw new \InvalidArgumentException(_('Select an IVR before enabling external paging.')); }
            foreach ($paging['external_ivr_ids'] as $id) {
                $ivr = $this->queryLivePagingIvr($id);
                if ($ivr === null) { $deletedMessage = _('A selected external paging IVR no longer exists. Review the IVR selection.'); continue; }
                if (in_array($paging['extension'], $ivr['entries'], true)) { throw new \InvalidArgumentException(_('The paging number is already assigned to a key in a selected IVR. Choose another paging number or remove that IVR key first.')); }
            }
        }
        $available = array_fill_keys(array_map('strval', $this->getConfiguredPjsipExtensionNumbers()), true);
        foreach ($legacy ? $paging['allowed_callers'] : [] as $caller) {
            if (!isset($available[$caller])) { $deletedMessage = _('An authorized legacy paging extension no longer exists. Update the caller selection.'); }
        }
        $normalizedGroups = array_column((array)($settings['announcement_groups'] ?? []), null, 'id');
        foreach ($paging['groups'] as $row) {
            $targets = $rawTargets[$row['group_id']] ?? null;
            if ($targets !== null && array_diff($targets, array_keys($available))) {
                $deletedMessage = _('A legacy paging audio recipient extension no longer exists. Update the group selection.');
                if (!isset($normalizedGroups[$row['group_id']]) && !array_intersect($targets, array_keys($available))) {
                    // The authenticated, structurally valid original audience
                    // lost every native phone. Do not invent a replacement.
                    continue;
                }
            }
            foreach (LivePagingConfig::resolvedGroups(array_replace($paging, ['groups' => [$row]]), (array)($settings['announcement_groups'] ?? [])) as $group) {
                foreach (['extensions' => _('audio recipient'), 'notify_extensions' => _('text recipient'), 'allowed_callers' => _('authorized caller')] as $field => $label) {
                    foreach ($group[$field] as $target) {
                        if (!isset($available[$target])) { $deletedMessage = sprintf(_('A paging %s extension no longer exists. Update the group selection.'), $label); }
                    }
                }
            }
        }
        if ($deletedMessage !== null) { throw new SlsDeletedPbxObjectException($deletedMessage); }
    }

    protected function queryLivePagingDialplan($extension)
    {
        $output = []; $status = 1;
        exec('/usr/bin/timeout --signal=TERM --kill-after=1 3 /usr/sbin/asterisk -rx '
            . escapeshellarg('dialplan show ' . $extension . '@from-internal') . ' 2>&1', $output, $status);
        if ($status !== 0) { throw new \RuntimeException('Paging extension conflict check is unavailable.'); }
        $text = implode("\n", $output);
        if (!preg_match("/(?:[Cc]ontext '|There is no existence of)/", $text)) { throw new \RuntimeException('Paging extension conflict check returned an unexpected response.'); }
        return $text;
    }

    public static function livePagingDialplanHasConflict($output, string $ownedContext = 'sls-live-paging')
    {
        $context = ''; $generated = false; $pattern = ''; $priorities = [];
        $isConflict = static function () use (&$context, &$generated, &$pattern, &$priorities, $ownedContext): bool {
            if (!$priorities || $context === $ownedContext) { return false; }
            // FreePBX includes this rejection fallback for every unused number.
            // Exempt only its complete stock body, never an outbound wildcard,
            // a custom route, or an exact extension in the same context.
            $reject = ['ResetCDR()', 'Set(CDR_PROP(disable)=true)', 'Progress()', 'Wait(1)',
                'Playback(silence/1&cannot-complete-as-dialed&check-number-dial-again,noanswer)',
                'Wait(1)', 'Congestion(20)', 'Hangup()'];
            $legacyReject = $reject; $legacyReject[1] = 'NoCDR()';
            return !($context === 'bad-number' && $generated && $pattern === '_X.'
                && ($priorities === $reject || $priorities === $legacyReject));
        };
        foreach (preg_split('/\R/', (string)$output) ?: [] as $line) {
            if (preg_match("/\\[\\s*(?:Included )?[Cc]ontext '([^']+)'/", $line, $match)) {
                if ($isConflict()) { return true; }
                $context = $match[1]; $generated = strpos($line, "created by 'pbx_config'") !== false;
                $pattern = ''; $priorities = [];
            }
            if (preg_match("/^\\s*'([^']+)'\\s*=>\\s*([0-9]+)\\.\\s*(.*?)\\s*\\[[^\\]]+\\]\\s*$/", $line, $match)) {
                if ($isConflict()) { return true; }
                $pattern = $match[1]; $priorities = [];
                if ((int)$match[2] !== 1) { return true; }
                $priorities[] = $match[3];
            } elseif (preg_match('/^\s*([0-9]+)\.\s*(.*?)\s*\[[^\]]+\]\s*$/', $line, $match)) {
                if ((int)$match[1] !== count($priorities) + 1) { return true; }
                $priorities[] = $match[2];
            } elseif (preg_match('/=>\s*[0-9]+\./', $line)) {
                // An unexpected CLI format cannot establish an unused number.
                if ($context !== $ownedContext) { return true; }
            }
        }
        return $isConflict();
    }

    private function assertLivePagingExtensionAvailable($extension)
    {
        $usage = $this->FreePBX->Extensions->checkUsage([(string)$extension], false);
        unset($usage['slsmassnotifyserver']);
        if (!empty($usage) || self::livePagingDialplanHasConflict($this->queryLivePagingDialplan($extension))) {
            throw new \InvalidArgumentException(_('That paging extension is already used or matches another PBX dialplan route. Choose an unused internal extension.'));
        }
    }

    public function getLivePagingExtensionUsage($extensions = true)
    {
        $settings = $this->getPendingSettings() ?? $this->getActiveSettings();
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        $panic=method_exists($this,'getPanicExtensionUsage') ? $this->getPanicExtensionUsage($extensions,$settings) : [];
        if ($paging['enabled'] !== '1' || ($extensions !== true && !in_array($paging['extension'], array_map('strval', (array)$extensions), true))) { return $panic; }
        return $panic + [$paging['extension'] => ['description' => _('SLL live paging menu'), 'status' => 'INUSE',
            'edit_url' => 'config.php?display=slsmassnotifyserver_paging']];
    }

    public function renderLivePagingPage(array $params = [])
    {
        $settings = $this->getPendingSettings() ?? $this->getActiveSettings();
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        $revision = hash('sha256', json_encode([$paging, $settings['announcement_groups'] ?? []], JSON_THROW_ON_ERROR));
        foreach ($paging['groups'] as &$row) { $row['has_pin'] = $row['pin_hash'] !== ''; unset($row['pin_hash']); }
        unset($row);
        $extensions = [];
        foreach ($this->getExtensionNameMap() as $extension => $name) { $extensions[] = ['extension' => (string)$extension, 'name' => $name]; }
        $active = LivePagingConfig::normalize((array)($this->getActiveSettings()['live_paging'] ?? []));
        return load_view(__DIR__ . '/views/paging.php', ['paging' => $paging, 'paging_revision' => $revision, 'settings' => $settings,
            'active_paging_enabled' => $active['enabled'] === '1', 'active_paging_extension' => $active['extension'],
            'has_pending_changes' => $this->getPendingSettings() !== null,
            'announcement_groups' => $settings['announcement_groups'] ?? [], 'available_extensions' => $extensions,
            'phone_inventory' => $this->phoneDisplayInventory(),
            'available_ivrs' => $this->getLivePagingIvrs(),
            'save_result' => $params['save_result'] ?? null, 'csrf_token' => $this->getCsrfToken(), 'hero_image' => self::HERO_IMAGE]);
    }

    private function requiredPagingPromptFiles(array $settings): array
    {
        if (LivePagingConfig::normalize((array)($settings['live_paging'] ?? []))['enabled'] === '1') {
            return LivePagingConfig::promptFiles($settings);
        }
        if (!array_filter($settings['automations']['rules'] ?? [], static fn($rule) =>
            ($rule['kind'] ?? '') === 'panic' && ($rule['enabled'] ?? false) === true && ($rule['dial_extension'] ?? '') !== '')) {
            return [];
        }
        $settings['live_paging'] = LivePagingConfig::defaults();
        return array_filter(LivePagingConfig::promptFiles($settings), static fn($role) => str_starts_with($role, 'panic_'), ARRAY_FILTER_USE_KEY);
    }

    private function assertLivePagingPromptsReady(array $settings)
    {
        $files = $this->requiredPagingPromptFiles($settings);
        if (!$files) { return; }
        $message = _('Paging prompts changed or are unavailable. Stage these settings and use Apply Config before activating them.');
        $account = function_exists('posix_getpwnam') ? posix_getpwnam('asterisk') : false;
        if (!is_array($account)) { throw new \DomainException($message); }
        foreach ($files as $relative) {
            $path = self::SOUNDS_DIR . '/paging/' . basename($relative) . '.wav';
            clearstatcache(true, $path);
            $before = @lstat($path);
            if (!is_array($before) || realpath($path) !== $path || ($before['mode'] & 0170000) !== 0100000 || $before['nlink'] !== 1
                || ($before['mode'] & 0777) !== 0640 || $before['uid'] !== $account['uid'] || $before['gid'] !== $account['gid'] || $before['size'] <= 44) {
                throw new \DomainException($message);
            }
            try { $valid = $this->isValidAnnouncementAudioCache($path); }
            catch (\Throwable $error) { throw new \DomainException($message, 0, $error); }
            if (!$valid) { throw new \DomainException($message); }
        }
    }

    private function ensureLivePagingPrompts(array $settings, bool $cachedOnly = false)
    {
        $files = $this->requiredPagingPromptFiles($settings);
        if (!$files) { return; }
        $directory = self::SOUNDS_DIR . '/paging';
        $native = function_exists('posix_getpwnam') ? posix_getpwnam('asterisk') : false;
        if (!is_array($native) || is_link($directory)) {
            throw new \RuntimeException(_('The live paging prompt directory or PBX account is unavailable.'));
        }
        if ($cachedOnly) {
            clearstatcache(true, $directory);
            $info = @lstat($directory);
            if ($info === false) {
                throw new SlsPagingPromptUnavailableException(_('The saved paging prompts have not been prepared.'));
            }
            if (realpath($directory) !== $directory || ($info['mode'] & 0177777) !== 0040750
                || $info['uid'] !== $native['uid'] || $info['gid'] !== $native['gid']) {
                throw new \RuntimeException(_('The live paging prompt directory failed its ownership check. Run protected repair.'));
            }
        } else {
            $this->ensureOwnedDirectory($directory, 0750);
        }
        $texts = null;
        foreach ($files as $key => $relative) {
            $destination = $directory . '/' . basename($relative) . '.wav';
            clearstatcache(true, $destination); $destinationBefore = @lstat($destination);
            if ($destinationBefore !== false && (($destinationBefore['mode'] & 0170000) !== 0100000
                || $destinationBefore['nlink'] !== 1 || realpath($destination) !== $destination)) {
                throw new \RuntimeException(_('A live paging prompt path is unsafe. Run protected repair.'));
            }
            if ($destinationBefore !== false && is_readable($destination) && $destinationBefore['size'] > 44) {
                if ($this->isValidAnnouncementAudioCache($destination)) {
                    if (!$cachedOnly) { $this->setPrivateOwnership($destination); }
                    clearstatcache(true, $destination); $secured = @lstat($destination);
                    if (!is_array($secured) || $secured['dev'] !== $destinationBefore['dev']
                        || $secured['ino'] !== $destinationBefore['ino'] || $secured['nlink'] !== 1
                        || ($secured['mode'] & 0177777) !== 0100640 || $secured['uid'] !== $native['uid'] || $secured['gid'] !== $native['gid']) {
                        throw new \RuntimeException(_('A live paging prompt changed while its ownership was secured. Run protected repair.'));
                    }
                    continue;
                }
            }
            if ($cachedOnly) {
                throw new SlsPagingPromptUnavailableException(_('The saved paging prompt is unavailable. Apply the SLL paging settings to prepare it.'));
            }
            if ($texts === null) {
                $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
                $texts = LivePagingConfig::promptTexts($paging['enabled'] === '1' ? $paging : LivePagingConfig::defaults(),
                    (array)($settings['announcement_groups'] ?? []), (array)($settings['automations'] ?? []));
            }
            $this->renderPagingPrompt($texts[$key], $settings, $destination, $destinationBefore);
            clearstatcache(true, $destination);
            if (!$this->isValidAnnouncementAudioCache($destination)) {
                throw new \RuntimeException(_('The published paging prompt could not be verified.'));
            }
        }
        if (!$cachedOnly) { $this->pruneLivePagingPrompts($settings); }
    }

    private function renderPagingPrompt(string $text, array $settings, string $destination, $previous): void
    {
        $helper = self::RUNTIME_DIR . '/sls_render_paging_prompt.py';
        $info = @lstat($helper);
        $native = function_exists('posix_getpwnam') ? posix_getpwnam('asterisk') : false;
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : -1;
        if (!is_array($info) || ($info['mode'] & 0170022) !== 0100000 || $info['uid'] !== 0 || $info['nlink'] !== 1
            || !is_array($native) || ($native['uid'] ?? 0) <= 0 || ($uid !== 0 && $uid !== $native['uid'])) {
            throw new \RuntimeException(_('The protected paging renderer or its PBX account could not be verified. Run Repair Installation.'));
        }
        $model = (string)($settings['announcement_piper_voice'] ?? $settings['piper_voice'] ?? self::PIPER_VOICE);
        $previousId = is_array($previous) ? $previous['dev'] . ':' . $previous['ino'] : 'missing';
        $volume = (string)$this->normalizeTtsVolume($settings['announcement_tts_volume'] ?? 25, 25);
        $command = array_merge($uid === 0 ? ['/usr/sbin/runuser', '-u', 'asterisk', '--'] : [],
            ['/usr/bin/timeout', '--kill-after=2', '1000', '/usr/bin/python3', '-I', '-B', $helper,
             basename($destination), $model, $previousId, $volume]);
        // Both CLI and web handlers pass an open descriptor to the native renderer.
        // No root-owned named speech workspace has to be opened by Asterisk.
        $input = tmpfile();
        if ($input === false) { throw new SlsPagingPromptUnavailableException(_('A private paging input file could not be created.')); }
        try {
            if (strlen($text) > 65536 || fwrite($input, $text) !== strlen($text) || !rewind($input)) {
                throw new SlsPagingPromptUnavailableException(_('The paging prompt text could not be staged.'));
            }
            $process = proc_open($command, [0 => $input, 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
                $pipes, '/', ['PATH' => '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG' => 'C.UTF-8', 'LC_ALL' => 'C.UTF-8']);
            if (!is_resource($process)) { throw new SlsPagingPromptUnavailableException(_('The native paging renderer could not start.')); }
            $detail = stream_get_contents($pipes[1], 512);
            fclose($pipes[1]);
            $status = proc_close($process);
        } finally {
            fclose($input);
        }
        if ($status === 0) { return; }
        if ($status === 73) {
            throw SlsPagingPromptUnavailableException::fromCapacityReport((string)$detail);
        }
        if (in_array($status, [65, 69, 74, 75, 124, 137], true)) {
            throw new SlsPagingPromptUnavailableException(sprintf(_('Paging prompt rendering did not finish (exit %d). Review the speech queue, prompt duration and voice readiness.'), $status));
        }
        throw new \RuntimeException(sprintf(_('The paging renderer refused its configuration, voice or protected file paths (exit %d). Run Help diagnostics.'), $status));
    }

    private function pruneLivePagingPrompts(array $prospective)
    {
        // Cleanup is optional: uncertain config state must preserve every file.
        // Strict disk reads avoid normalization/default fallbacks hiding a
        // malformed or unreadable active/pending configuration.
        try {
            $states = [$prospective, \SLS\MassNotify\LivePagingSession::loadSettings(self::SETTINGS_JSON)];
            $paths = [self::PENDING_SETTINGS_JSON];
            foreach (['LEGACY_PENDING_SETTINGS_JSON', 'LEGACY_OLD_PENDING_SETTINGS_JSON'] as $constant) {
                $name = self::class . '::' . $constant;
                if (defined($name)) { $paths[] = constant($name); }
            }
            foreach (array_unique($paths) as $path) {
                if (!is_readable(dirname($path)) || !is_executable(dirname($path))) { return; }
                if (@lstat($path) !== false || is_link($path)) {
                    $states[] = \SLS\MassNotify\LivePagingSession::loadSettings($path);
                }
            }
            $keep = [];
            foreach ($states as $state) {
                foreach (LivePagingConfig::promptFiles($state) as $relative) { $keep[basename($relative) . '.wav'] = true; }
            }
            $refresh = [];
            foreach ($this->requiredPagingPromptFiles($prospective) as $relative) { $refresh[] = basename($relative) . '.wav'; }
            $manifest = json_encode(['keep' => array_keys($keep), 'refresh' => $refresh], JSON_THROW_ON_ERROR);
        } catch (\Throwable $ignored) { return; }

        // Anchor each parent component without following links. Only our exact
        // generated names, single-link regular files, and old use times qualify.
        // Refreshing prospective prompts also protects a concurrent activation
        // and calls already in progress for much longer than the 30-minute cap.
        $program = <<<'PY'
import json, os, re, stat, sys, time
path = sys.argv[1]
manifest = json.loads(sys.argv[2])
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
directory = os.open('/', flags)
try:
    for component in [part for part in path.split('/') if part]:
        next_directory = os.open(component, flags, dir_fd=directory)
        os.close(directory)
        directory = next_directory
    keep = set(manifest['keep'])
    for name in manifest['refresh']:
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit(2)
        os.utime(name, None, dir_fd=directory, follow_symlinks=False)
    cutoff = time.time() - 86400
    removed = False
    for name in os.listdir(directory):
        if name in keep or not re.fullmatch(r'[0-9a-f]{64}\.wav', name):
            continue
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mtime >= cutoff:
                continue
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_nlink, current.st_mtime) != (metadata.st_dev, metadata.st_ino, 1, metadata.st_mtime):
                continue
            os.unlink(name, dir_fd=directory)
            removed = True
        except OSError:
            continue
    if removed:
        os.fsync(directory)
finally:
    os.close(directory)
PY;
        $output = []; $status = 1;
        @exec('/usr/bin/python3 -I -c ' . escapeshellarg($program) . ' ' . escapeshellarg(self::SOUNDS_DIR . '/paging') . ' ' . escapeshellarg($manifest) . ' 2>/dev/null', $output, $status);
    }

    public function myDialplanHooks() { return 500; }

    public function getLivePagingIvrs(): array
    {
        try {
            $db = $this->FreePBX->Database();
            $rows = $db->query('SELECT id, name FROM ivr_details ORDER BY name LIMIT 101')->fetchAll(\PDO::FETCH_ASSOC);
            $statement = $db->prepare('SELECT selection FROM ivr_entries WHERE ivr_id = ?');
            $result = [];
            foreach ($rows as $row) {
                $id = (string)$row['id'];
                if (!preg_match('/^[1-9][0-9]{0,8}$/D', $id)) { continue; }
                $statement->execute([$id]);
                $result[] = ['id'=>$id, 'name'=>(string)$row['name'], 'entries'=>array_map('strval', $statement->fetchAll(\PDO::FETCH_COLUMN))];
            }
            return $result;
        } catch (\Throwable $error) { return []; }
    }

    /** Query selected IDs exactly; UI inventory failures/truncation are not deletion evidence. */
    protected function queryLivePagingIvr(string $id): ?array
    {
        $db = $this->FreePBX->Database();
        $statement = $db->prepare('SELECT id FROM ivr_details WHERE id = ? LIMIT 2');
        if ($statement->execute([$id]) !== true) { throw new \RuntimeException(_('The PBX IVR inventory could not be read.')); }
        $rows = $statement->fetchAll(\PDO::FETCH_COLUMN);
        if (!$rows) { return null; }
        if (count($rows) !== 1 || (string)$rows[0] !== $id) { throw new \RuntimeException(_('The PBX IVR inventory is invalid.')); }
        $statement = $db->prepare('SELECT selection FROM ivr_entries WHERE ivr_id = ? LIMIT 1001');
        if ($statement->execute([$id]) !== true) { throw new \RuntimeException(_('The PBX IVR entries could not be read.')); }
        $entries = $statement->fetchAll(\PDO::FETCH_COLUMN);
        if (count($entries) > 1000) { throw new \RuntimeException(_('The selected PBX IVR exceeds the supported entry limit.')); }
        return ['id' => $id, 'entries' => array_map('strval', $entries)];
    }

    public function getLivePagingExternalDestinations(): array
    {
        $settings = $this->getPendingSettings() ?? $this->getActiveSettings();
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        if ($paging['enabled'] !== '1' || ($paging['external_access'] ?? '0') !== '1'
            || !array_filter($paging['groups'], static fn($r) => ($r['allow_external'] ?? '0') === '1')) { return []; }
        return [['destination' => 'sls-live-paging-external,s,1',
            'description' => _('SLL external paging · group PIN required')]];
    }

    public function doDialplanHook(&$ext, $engine, $priority)
    {
        if ($engine !== 'asterisk') { return; }
        // Only a committed revision can authorize calls to the AGIs. Activation
        // and prompt preparation complete before the first route is published.
        $cachedOnly = !$this->applyStagedSettingsForPbxReload(true);
        $settings = $this->getActiveSettings();
        $rawSettings = $this->reloadHasLegacyPagingGroups($settings) ? $this->rawSettingsForPbxReload($settings, false) : $settings;
        if (method_exists($this,'addPanicDialplan')) { $this->addPanicDialplan($ext, $settings, $cachedOnly); }
        $paging = LivePagingConfig::normalize((array)($settings['live_paging'] ?? []));
        if ($paging['enabled'] !== '1') { return; }
        try { $this->validateLivePagingSelection($paging, $settings, $rawSettings); }
        catch (SlsDeletedPbxObjectException $error) {
            // The AGI reads unchanged saved settings, so omit the entire menu
            // rather than publish an authorization projection it cannot use.
            $this->warnDeletedPbxObjectDuringReload('paging');
            return;
        }
        $this->assertLivePagingExtensionAvailable($paging['extension']);
        // Panic shortcuts use their own confirmation audio. Their media
        // availability cannot invalidate the separately authorized paging menu.
        $menu = $settings;
        if (isset($menu['automations']['rules'])) { $menu['automations']['rules'] = []; }
        try { $this->ensureLivePagingPrompts($menu, $cachedOnly); }
        catch (SlsPagingPromptUnavailableException $error) {
            $this->warnPagingPromptsDuringReload(false, $error);
            return;
        }
        // A raw local AGI entry intentionally avoids FreePBX's optional FastAGI
        // rewriting: this protected executable reads its own standard AGI pipe.
        $ext->add('sls-live-paging', $paging['extension'], '', new \ext_setvar('AGISIGHUP', 'no'));
        $ext->add('sls-live-paging', $paging['extension'], '', new \extension('AGI(' . self::RUNTIME_DIR . '/sls_mass_notify_live_paging.php)'));
        $ext->add('sls-live-paging', $paging['extension'], '', new \ext_hangup());
        $ext->addInclude('from-internal-additional', 'sls-live-paging');
        if (($paging['external_access'] ?? '0') === '1') {
            // No public pattern or from-trunk include: an administrator must
            // explicitly choose this destination in an IVR or inbound route.
            $ext->add('sls-live-paging-external', 's', '', new \ext_setvar('AGISIGHUP', 'no'));
            $ext->add('sls-live-paging-external', 's', '', new \extension('AGI(' . self::RUNTIME_DIR . '/sls_mass_notify_live_paging.php)'));
            $ext->add('sls-live-paging-external', 's', '', new \ext_hangup());
            foreach ($paging['external_ivr_ids'] as $id) {
                // Add an exact number to the selected IVR. Never expose this
                // through from-trunk or the general external direct-dial route.
                $ext->add('ivr-'.$id, $paging['extension'], '', new \extension('Goto(sls-live-paging-external,s,1)'));
            }
        }
        $ext->add('sls-live-paging-autoanswer', 's', '', new \ext_setvar('SLS_PAGING_TARGET', '${CHANNEL(endpoint)}'));
        $ext->add('sls-live-paging-autoanswer', 's', '', new \ext_gosub(1, 's', 'sls-alert-autoanswer', '${SLS_PAGING_TARGET}'));
        $ext->add('sls-live-paging-autoanswer', 's', '', new \ext_return());
        // ConfBridge's caller-only menu executes this context directly. Let it
        // fall through so it restores the original IVR/Gosub stack itself.
        $ext->add('sls-live-paging-ready', 's', '', new \extension('AGI(' . self::RUNTIME_DIR . '/sls_mass_notify_live_paging.php,--ready)'));
        $ext->add('sls-live-paging-ready', 's', '', new \extension('StopPlayTones()'));
    }
}
