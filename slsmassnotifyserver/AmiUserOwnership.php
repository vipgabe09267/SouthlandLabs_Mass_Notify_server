<?php
declare(strict_types=1);
namespace SLS\MassNotify;

/** A historical username alone is not evidence that SLL owns an AMI account. */
final class AmiUserOwnership
{
    public static function matches(array $row, string $name, string $secretHash): bool
    {
        if (($row['name'] ?? null) !== $name || !preg_match('/^[a-f0-9]{64}$/D', $secretHash)
            || !is_string($row['secret'] ?? null) || $row['secret'] === ''
            || !hash_equals($secretHash, hash('sha256', $row['secret']))
            || !is_string($row['read'] ?? null) || ($row['write'] ?? null) !== $row['read']
            || !in_array($row['read'], ['system,call,originate','system,call,originate,reporting'], true)
            || !in_array($row['writetimeout'] ?? null, [1000, '1000'], true)
            || !is_string($row['permit'] ?? null) || !is_string($row['deny'] ?? null)) { return false; }
        $permit = explode('&', $row['permit']);
        $allowed = ['127.0.0.1/255.255.255.255', '127.0.0.1/32', '::1/128'];
        $deny = explode('&', $row['deny']);
        // Additional site-specific deny entries can change the administrator's policy.
        return $permit !== [] && !array_diff($permit, $allowed)
            && !array_diff($deny, ['0.0.0.0/0.0.0.0', '0.0.0.0/0', '::/0'])
            && (in_array('0.0.0.0/0.0.0.0', $deny, true) || in_array('0.0.0.0/0', $deny, true))
            && (!in_array('::1/128', $permit, true) || in_array('::/0', $deny, true));
    }

    /** Identify the generated fallback from the protected credential and the complete ACL. */
    public static function fileAccount(string $text, string $name, string $proof, bool $requireUnusedName = false): ?string
    {
        $begin = 'BEGIN SLS Mass Notifications AMI';
        $end = 'END SLS Mass Notifications AMI';
        $headers = preg_match_all('/^[ \t]*\[[ \t]*' . preg_quote($name, '/') . '[ \t]*\]/im', $text);
        if (strpos($text, $begin) === false && strpos($text, $end) === false) {
            if ($requireUnusedName && $headers !== 0) {
                throw new \RuntimeException('The configured AMI identity already has an unmanaged file section.');
            }
            return null;
        }
        if (substr_count($text, $begin) !== 1 || substr_count($text, $end) !== 1 || $headers !== 1
            || !preg_match('/^(; |# |;-- )BEGIN SLS Mass Notifications AMI( --)?\r?$/m', $text, $start, PREG_OFFSET_CAPTURE)
            || (($start[1][0] === ';-- ') !== isset($start[2]))) {
            throw new \RuntimeException('The managed AMI file section is ambiguous. Preserve the file for review.');
        }
        $beginOffset = $start[0][1] + strlen($start[0][0]);
        $endMarker = str_replace($begin, $end, rtrim($start[0][0], "\r"));
        if (!preg_match('/^' . preg_quote($endMarker, '/') . '\r?$/m', $text, $finish, PREG_OFFSET_CAPTURE, $beginOffset)
            || $finish[0][1] - $beginOffset > 4096) {
            throw new \RuntimeException('The managed AMI file section is incomplete or oversized.');
        }
        $body = trim(substr($text, $beginOffset, $finish[0][1] - $beginOffset), "\r\n");
        $lines = preg_split('/\r?\n/', $body);
        $header = array_shift($lines);
        $credential = array_shift($lines) ?? '';
        $legacy = ['deny = 0.0.0.0/0.0.0.0', 'permit = 127.0.0.1/255.255.255.255',
            'read = system,call,originate', 'write = system,call,originate'];
        $current = ['deny = 0.0.0.0/0.0.0.0', 'deny = ::/0', 'permit = 127.0.0.1/255.255.255.255',
            'permit = ::1/128', 'read = '.self::RIGHTS, 'write = '.self::RIGHTS];
        if ($header !== '['.$name.']' || !preg_match('/^secret = ([!-~]{1,128})$/D', $credential, $secret)
            || !hash_equals($proof, hash('sha256', $secret[1])) || ($lines !== $legacy && $lines !== $current)) {
            throw new \RuntimeException('The managed AMI file identity, credential or policy changed. Preserve it for review.');
        }
        return $name;
    }

    private static function nativeTable($database): bool
    {
        $table = $database->prepare('SHOW TABLES LIKE ?');
        if (!$table->execute(['manager'])) { throw new \RuntimeException('Could not inspect the optional Manager table.'); }
        return $table->fetchColumn() !== false;
    }

    private const DENY = '0.0.0.0/0.0.0.0&::/0';
    private const PERMIT = '127.0.0.1/255.255.255.255&::1/128';
    private const RIGHTS = 'system,call,originate,reporting';
    private const ROW_PREDICATE = 'manager_id = ? AND BINARY name = ? AND BINARY secret = ? AND BINARY deny = ? AND BINARY permit = ? AND BINARY `read` = ? AND BINARY `write` = ? AND writetimeout = ?';

    private static function singleRow($lookup, string $name): ?array
    {
        $lookup->execute([$name]);
        $rows = $lookup->fetchAll(\PDO::FETCH_ASSOC);
        if (count($rows) > 1) {
            throw new \RuntimeException('The native AMI account identity is ambiguous. Preserve the existing accounts.');
        }
        $row = $rows[0] ?? null;
        if ($row !== null && !preg_match('/^[1-9][0-9]{0,19}$/D', (string)($row['manager_id'] ?? ''))) {
            throw new \RuntimeException('The native AMI account identifier could not be verified.');
        }
        return $row;
    }

    private static function originalFields(array $row): array
    {
        return array_map(static fn($key) => $row[$key],
            ['manager_id', 'name', 'secret', 'deny', 'permit', 'read', 'write', 'writetimeout']);
    }

    private static function canonical(array $row): bool
    {
        return $row['deny'] === self::DENY && $row['permit'] === self::PERMIT
            && $row['read'] === self::RIGHTS && $row['write'] === self::RIGHTS
            && in_array($row['writetimeout'], [1000, '1000'], true);
    }

    /** Return false only when no native target exists and a managed-file fallback can be used. */
    public static function reconcile($database, $manager, string $name, string $secret, string $pbxUser): bool
    {
        if ($secret === '' || strcasecmp($name, $pbxUser) === 0 || !preg_match('/^[A-Za-z0-9_.-]{1,80}$/D', $name)) {
            throw new \RuntimeException('Invalid dedicated SLL AMI identity.');
        }
        if (!self::nativeTable($database)) { return false; }

        $legacyName = $name !== 'sls_mass_notify' && strcasecmp('sls_mass_notify', $pbxUser) !== 0 ? 'sls_mass_notify' : null;
        $proof = hash('sha256', $secret);
        $outerTransaction = $database->inTransaction();
        if ($manager !== null) {
            // Stock Manager indexes only manager_id. A name-based locking read for a
            // no-change repair would lock unrelated PBX users until the outer commit.
            $read = $database->prepare('SELECT * FROM manager WHERE name = ?');
            $row = self::singleRow($read, $name);
            if ($row !== null && self::matches($row, $name, $proof) && self::canonical($row)) {
                $legacy = $legacyName === null ? null : self::singleRow($read, $legacyName);
                if ($legacy === null || !self::matches($legacy, $legacyName, $proof)) {
                    if (!$outerTransaction) { return true; }
                    // Recheck this specific identity against the current database state
                    // when the caller's consistent-read snapshot could predate an edit.
                    $current = $database->prepare('SELECT * FROM manager WHERE manager_id = ? LOCK IN SHARE MODE');
                    $current->execute([$row['manager_id']]);
                    $confirmed = $current->fetch(\PDO::FETCH_ASSOC);
                    if ($confirmed && self::matches($confirmed, $name, $proof) && self::canonical($confirmed)) {
                        return true;
                    }
                }
            }
        }

        $savepoint = $outerTransaction ? 'sll_ami_' . bin2hex(random_bytes(8)) : null;
        if ($savepoint === null) { $database->beginTransaction(); }
        else { $database->exec('SAVEPOINT ' . $savepoint); }
        try {
            $result = self::reconcileLocked($database, $manager, $name, $secret, $proof, $legacyName);
            if ($savepoint === null) { $database->commit(); }
            else { $database->exec('RELEASE SAVEPOINT ' . $savepoint); }
            return $result;
        } catch (\Throwable $error) {
            if ($database->inTransaction()) {
                if ($savepoint === null) { $database->rollBack(); }
                else {
                    $database->exec('ROLLBACK TO SAVEPOINT ' . $savepoint);
                    $database->exec('RELEASE SAVEPOINT ' . $savepoint);
                }
            }
            throw $error;
        }
    }

    private static function reconcileLocked($database, $manager, string $name, string $secret, string $proof, ?string $legacyName): bool
    {
        $lookup = $database->prepare('SELECT * FROM manager WHERE name = ? FOR UPDATE');
        $row = self::singleRow($lookup, $name);
        if ($row !== null && ($manager === null || !self::matches($row, $name, $proof))) {
            throw new \RuntimeException('The configured AMI name belongs to an existing account that cannot be safely reconciled.');
        }
        if ($manager === null) { return false; }
        $legacy = $legacyName === null ? null : self::singleRow($lookup, $legacyName);
        if ($row === null) {
            try {
                $manager->add_manager($name, $secret, self::DENY, self::PERMIT, self::RIGHTS, self::RIGHTS, 1000);
            } catch (\Throwable $error) {
                // Stock Manager indicates a name or administrator conflict explicitly.
                // A failed INSERT alone does not prove the native target is absent.
                if (in_array((int)$error->getCode(), [110, 130], true)) {
                    throw new \RuntimeException('The native Manager reported a conflicting account. Preserve the existing policy.');
                }
                if (self::singleRow($lookup, $name) === null) { return false; }
            }
        } elseif (!self::canonical($row)) {
            $update = $database->prepare('UPDATE manager SET deny = ?, permit = ?, `read` = ?, `write` = ? WHERE ' . self::ROW_PREDICATE);
            $update->execute(array_merge([self::DENY, self::PERMIT, self::RIGHTS, self::RIGHTS], self::originalFields($row)));
            if ($update->rowCount() !== 1) { throw new \RuntimeException('The owned AMI policy changed while it was being updated.'); }
        }
        $confirmed = self::singleRow($lookup, $name);
        if ($confirmed === null || !self::matches($confirmed, $name, $proof) || !self::canonical($confirmed)
            || ($row !== null && (string)$confirmed['manager_id'] !== (string)$row['manager_id'])) {
            throw new \RuntimeException('The dedicated native AMI account could not be confirmed. Preserve the existing policy.');
        }
        if ($legacy !== null && self::matches($legacy, $legacyName, $proof)) {
            $delete = $database->prepare('DELETE FROM manager WHERE ' . self::ROW_PREDICATE);
            $delete->execute(self::originalFields($legacy));
            if ($delete->rowCount() !== 1) { throw new \RuntimeException('The previous dedicated AMI account changed during migration.'); }
        }
        return true;
    }

    private static function ownedRows($database, array $names, string $proof, string $pbxUser, ?string $fileName = null): array
    {
        if ($fileName !== null && (!in_array($fileName, $names, true) || strcasecmp($fileName, $pbxUser) === 0)) {
            throw new \RuntimeException('The managed AMI file conflicts with the configured or administrative identity.');
        }
        if (!self::nativeTable($database)) { return []; }
        $lookup = $database->prepare('SELECT * FROM manager WHERE name = ?');
        $owned = [];
        foreach (array_unique(array_filter($names, 'is_string')) as $name) {
            if (!preg_match('/^[A-Za-z0-9_.-]{1,80}$/D', $name) || strcasecmp($name, $pbxUser) === 0) { continue; }
            $row = self::singleRow($lookup, $name);
            if ($row !== null && self::matches($row, $name, $proof)) { $owned[] = $row; }
            elseif ($row !== null && $name === $fileName) {
                throw new \RuntimeException('The managed AMI file name conflicts with a different native account.');
            }
        }
        return $owned;
    }

    public static function ownedNames($database, array $names, string $proof, string $pbxUser, ?string $fileName = null): array
    {
        $owned = array_column(self::ownedRows($database, $names, $proof, $pbxUser, $fileName), 'name');
        if ($fileName !== null && !in_array($fileName, $owned, true)) { $owned[] = $fileName; }
        return $owned;
    }

    public static function remove($database, array $names, string $secretHash, string $pbxUser): array
    {
        $rows = self::ownedRows($database, $names, $secretHash, $pbxUser);
        $removed = [];
        if (!$rows) { return $removed; }
        $delete = $database->prepare('DELETE FROM manager WHERE ' . self::ROW_PREDICATE);
        foreach ($rows as $row) {
            $delete->execute(self::originalFields($row));
            if ($delete->rowCount() === 1) { $removed[] = $row['name']; }
        }
        return $removed;
    }
}
