<?php
namespace FreePBX\modules;

/** Read-only local Apache probes. Never resolve a public address or follow redirects. */
final class SlsLocalWebProbe
{
	public static function mediaAccess(array $settings, ?iterable $observations = null): array
	{
		require_once __DIR__.'/api/sls-mass-notify/media-policy.php';
		try { \SLS\MassNotify\MediaAccess::normalize(array_key_exists('media_access', $settings) ? $settings['media_access'] : []); }
		catch (\DomainException $error) { return ['ok'=>false, 'message'=>$error->getMessage()]; }
		$path = '/sls_mass_notify/media_probe_' . bin2hex(random_bytes(12)) . '.png';
		$observations = $observations ?? self::responses($settings['public_pbx_host'] ?? '', $path, ['Accept: application/json'], 2);
		try {
		foreach ($observations as $response) {
				if (!is_array($response) || !is_int($response['status'] ?? null) || !is_array($response['headers'] ?? null)
					|| count($response['headers']) > 100 || !is_string($response['body'] ?? null) || strlen($response['body']) > 262144) { continue; }
			$marked = false;
				foreach ($response['headers'] as $header) { if (is_string($header) && preg_match('/^X-SLS-Media-Policy:\s*1\s*$/iD', $header)) { $marked = true; break; } }
			if (!$marked) { continue; }
					try { $body = \SLS\MassNotify\ApiSecurity::jsonObject($response['body'], false, 16); }
					catch (\Throwable $error) { continue; }
			if (($response['status'] === 404 && ($body['error'] ?? '') === 'media_not_found')
				|| ($response['status'] === 403 && ($body['error'] ?? '') === 'media_network_denied')) {
				return ['ok'=>true, 'message'=>_('Generated media passes through the configured access policy. No file was created or notification sent.')];
			}
			if ($response['status'] === 503 && ($body['error'] ?? '') === 'media_access_configuration_unavailable') {
				return ['ok'=>false, 'message'=>_('The media route cannot read a valid protected configuration. Review Media Access settings and use Repair Installation to restore file permissions.')];
			}
		}
		} catch (\RuntimeException $error) {
			return ['ok'=>false, 'message'=>_('Local PBX route authority is unavailable. Use the authenticated root-assisted installation check; no media request was sent without route authority.')];
		}
		return ['ok'=>false, 'message'=>_('The generated-media policy route could not be verified. Run Repair Installation and inspect any custom Apache alias or virtual-host overrides.')];
	}

	private static function nativeInventory($provided, string $environment, string $kind): string
	{
		if ($provided === null) {
			$inherited = getenv($environment);
			if (is_string($inherited) && $inherited !== '') { $provided = $inherited; }
		}
		if ($provided === null) {
			$command = '/usr/bin/timeout 5 /usr/sbin/apache2ctl -t -D ' . $kind;
			if ($kind === 'DUMP_CONFIG') {
				$command .= ' -C ' . escapeshellarg('LoadModule info_module /usr/lib/apache2/modules/mod_info.so');
			}
			$output = []; $status = 1;
			@exec($command . ' 2>/dev/null', $output, $status);
			if ($status !== 0) { throw new \RuntimeException('Local PBX route authority is unavailable. Use the authenticated root-assisted installation check; credentials were not sent.'); }
			$provided = implode("\n", $output);
		}
		if (!is_string($provided)) { throw new \InvalidArgumentException('Apache route inventory must be text.'); }
		if (strlen($provided) > 65536 || str_contains($provided, "\0")) {
			throw new \RuntimeException('Apache route inventory exceeds its inspection bound; credentials were not sent.');
		}
		return $provided;
	}

	/** Read one bounded, canonical file whose parents and object are controlled by root or the PBX account. */
	private static function dispatcherFileHash(string $path, int $limit, array $account): ?string
	{
		$uid = $account['uid']; $gid = $account['gid'];
		$trusted = static function ($info, int $access) use ($uid, $gid): bool {
			if (!is_array($info) || !in_array($info['uid'], [0, $uid], true)
				|| !in_array($info['gid'], [0, $gid], true) || ($info['mode'] & 0002)) { return false; }
			$shift = $info['uid'] === $uid ? 6 : ($info['gid'] === $gid ? 3 : 0);
			return (bool)(($info['mode'] >> $shift) & $access);
		};
		$snapshot = static function (string $file) {
			clearstatcache(true, $file);
			return @lstat($file);
		};
		for ($directory = dirname($path); ; $directory = dirname($directory)) {
			$info = $snapshot($directory);
			if (!$trusted($info, 1) || ($info['mode'] & 0170000) !== 0040000) { return null; }
			if ($directory === '/') { break; }
		}
		$file = $snapshot($path);
		if (!$trusted($file, 4) || ($file['mode'] & 0177000) !== 0100000
			|| $file['nlink'] !== 1 || $file['size'] < 1 || $file['size'] > $limit) { return null; }
		$handle = @fopen($path, 'rb');
		if (!$handle) { return null; }
		try {
			// Reads may advance atime. Every authority-bearing field must remain stable.
			$same = static function ($info) use ($file): bool {
				if (!is_array($info)) { return false; }
				foreach (['dev','ino','mode','nlink','uid','gid','size','mtime','ctime'] as $key) {
					if ($file[$key] !== $info[$key]) { return false; }
				}
				return true;
			};
			if (!$same(fstat($handle))) { return null; }
			$bytes = stream_get_contents($handle, $limit + 1);
			if (!is_string($bytes) || strlen($bytes) !== $file['size']
				|| !$same(fstat($handle)) || !$same($snapshot($path))) { return null; }
			return hash('sha256', $bytes);
		} finally { fclose($handle); }
	}

	private static function legacyDispatcher(string $from, string $to, string $route): bool
	{
		if ($to !== '/var/www/html' . $from . '.php') { return false; }
		if ($from === '/api/sipnotify' && in_array($route, [$from . '/desktop', $from . '/desktop/stream'], true)) {
			$wrapper = "<?php\nrequire __DIR__ . '/sipnotify/index.php';\n";
			$indexes = ['cbe2527bb7dd5284eb6da6228cae62effa8fbed952a830fa0e6fe3dd22700ca9'];
		} elseif ($from === '/api/sls-mass-notify' && (in_array($route, [$from, $from . '/', $from . '/sms-callback.php', $from . '/media.php'], true)
			|| preg_match('#^/sls_mass_notify/[A-Za-z0-9][A-Za-z0-9_.-]{0,179}\.(?:png|xml)$#D', $route))) {
			$wrapper = "<?php\n// Southland Servers Mass Notifications Server by the Southland Servers Group\n"
				. "require __DIR__ . '/sls-mass-notify/index.php';\n";
			// Signed 0.2.0 target and both published 0.1.9 predecessors used in recovery.
			$indexes = ['41fedcb511ae952bf26d414a38244771c6309486b68e4df72512a1ef6f4bd809',
				'd68f3ad291af0d4340c3141c447e3488cde313935a185a087500e1e1cca5c9d1',
				'b2136d5088a77587c468194254f889a4bae380461db26d50f888c72dbaa1f02c'];
		} else { return false; }
		if (!function_exists('posix_getpwnam')) { return false; }
		$account = posix_getpwnam('asterisk');
		if (!is_array($account) || ($account['uid'] ?? 0) <= 0 || ($account['gid'] ?? 0) <= 0) { return false; }
		if (self::dispatcherFileHash($to, strlen($wrapper), $account) !== hash('sha256', $wrapper)) { return false; }
		$published = self::dispatcherFileHash('/var/www/html' . $from . '/index.php', 131072, $account);
		return in_array($published, $indexes, true) && $published === self::dispatcherFileHash(
			'/var/www/html/admin/modules/slsmassnotifyserver' . $from . '/index.php', 131072, $account);
	}

	private static function binding(string $text): ?array
	{
		$text = trim($text);
		if (ctype_digit($text)) { $text = '*:' . $text; }
		if (!preg_match('/^(\*|_default_|[0-9.]+|\[[0-9a-f:]+\]):([0-9]{1,5})$/iD', $text, $match)) { return null; }
		$port = (int)$match[2]; if ($port < 1 || $port > 65535) { return null; }
		$address = strtolower($match[1]);
		if ($address === '_default_') { $address = '*'; }
		$addresses = match ($address) {
			'*' => ['127.0.0.1', '::1'], '0.0.0.0', '127.0.0.1' => ['127.0.0.1'],
			'[::]' => ['::1'], '[::1]' => ['::1'], default => [],
		};
		return ['key'=>$address . ':' . $port, 'port'=>$port, 'addresses'=>$addresses];
	}

	private static function routeRelevant(array $sections, string $path): bool
	{
		foreach ($sections as [$name,$value]) {
			if ($name === 'directory') {
				if (!str_starts_with($value, '/') || strpbrk($value, '*?[') !== false || str_contains($value, '${') || str_contains($value, '%{')) { continue; }
				$value = rtrim($value, '/'); $file = '/var/www/html' . $path;
				if ($value !== '' && $value !== '/' && $file !== $value && !str_starts_with($file, $value . '/')) { return false; }
			} elseif ($name === 'location') {
				if (!str_starts_with($value, '/') || strpbrk($value, '*?[') !== false || str_contains($value, '${') || str_contains($value, '%{')) { continue; }
				$value = rtrim($value, '/');
				if ($value !== '' && $path !== $value && !str_starts_with($path, $value . '/')) { return false; }
			} elseif ($name === 'filesmatch' && self::staticFilesUnrelated($value, $path)) { return false; }
		}
		return true;
	}

	private static function staticFilesUnrelated(string $value, string $path): bool
	{
		$value = strtolower($value);
		if (str_starts_with($value, '(?i)')) { $value = substr($value, 4); }
		if (str_starts_with($value, '^')) { $value = substr($value, 1); }
		if (str_starts_with($value, '.*') || str_starts_with($value, '.+')) { $value = substr($value, 2); }
		if (!str_starts_with($value, chr(92).'.') || !str_ends_with($value, '$')) { return false; }
		$suffix = substr($value, 2, -1);
		if (str_starts_with($suffix, '(?:') && str_ends_with($suffix, ')')) { $suffix = substr($suffix, 3, -1); }
		elseif (str_starts_with($suffix, '(') && str_ends_with($suffix, ')')) { $suffix = substr($suffix, 1, -1); }
		if (!preg_match('/^[a-z0-9]+(?:\|[a-z0-9]+)*$/D', $suffix)) { return false; }
		$suffixes = explode('|', $suffix);
		// Debian's PHP source-view handler matches only .phps. It cannot
		// govern PHP APIs or generated images; matching .phps/PATH_INFO stays relevant.
		if (array_diff($suffixes, ['css','js','png','jpg','jpeg','gif','svg','ico','woff','woff2','ttf','eot','map','phps'])) { return false; }
		$extensions = [];
		foreach (explode('/', $path) as $component) {
			$extension = strtolower(pathinfo($component, PATHINFO_EXTENSION));
			if ($extension !== '') { $extensions[] = $extension; }
		}
		// An earlier component may be the filename followed by PATH_INFO.
		if (array_intersect($extensions, $suffixes)) { return false; }
		if ($extensions) { return true; }
		// Publisher API directory/extensionless routes dispatch through PHP.
		// Unknown extensionless routes have no independently qualified filename.
		return (bool)preg_match('#^/api/(?:sipnotify|sls-mass-notify)(?:/|$)#D', $path);
	}

	/** Known internal URI redirects that can execute the server's rules a second time. */
	private static function dispatchPaths(string $path): array
	{
		$paths = [$path];
		if (str_starts_with($path, '/sls_mass_notify/')) { $paths[] = '/api/sls-mass-notify/media.php'; }
		if (preg_match('#^(/api/(?:sipnotify|sls-mass-notify))(?:/|$)#D', $path, $match)) {
			$paths[] = $match[1] . '/index.php';
			if ($path === $match[1]) { $paths[] = $path . '/'; }
		}
		return array_unique($paths);
	}

	/** PCRE shared by Apache and PHP, restricted to anchored literal paths and bounded choices. */
	private static function literalPathMatch(string $pattern, string $path, bool $noCase = false): ?bool
	{
		if (strlen($pattern) > 384 || !str_starts_with($pattern, '^/') || substr_count($pattern, '(') > 8
			|| substr_count($pattern, '|') > 12 || substr_count($pattern, '?') > 12) { return null; }
		// Only slash, literal basename characters, escaped dot, group/optional-group,
		// alternation and end-anchor tokens. No inline modes, escapes or repetitions.
		$tokens = preg_replace('~[A-Za-z0-9/_-]+|\\\\\.|\(\?:|\(|\)\??|\||\$~', '', substr($pattern, 1));
		if ($tokens !== '') { return null; }
		$result = @preg_match('~(*LIMIT_MATCH=2048)(*LIMIT_DEPTH=32)' . $pattern . '~D' . ($noCase ? 'i' : ''), $path);
		return $result === false ? null : $result === 1;
	}

	private static function redirectMatchUnrelated(string $value, array $paths): bool
	{
		// Native RedirectMatch [status] expression destination. Restrict the
		// destination to a literal local path or the root inspector's redaction.
		if (!preg_match('~^(?:(?:30[12378]|permanent|temp|seeother)\s+)?(?:"([^"\s]+)"|([^"\s]+))\s+(?:"(/[A-Za-z0-9_./-]+)"|(/[A-Za-z0-9_./-]+)|UNQUALIFIED_REMOTE_HANDLER)$~iD', $value, $match)) { return false; }
		$pattern = $match[1] !== '' ? $match[1] : $match[2];
		if (!str_ends_with($pattern, '$')) { return false; }
		foreach ($paths as $path) { if (self::literalPathMatch($pattern, $path) !== false) { return false; } }
		return true;
	}

	private static function conditionExcludes(array $conditions, string $path): bool
	{
		// Apache ANDs groups of OR-linked conditions. An unknown alternative
		// may match. Every alternative in one complete group must be proven false.
		$excluded = false; $groupFalse = true; $orNext = false;
		foreach ($conditions as $value) {
			if (!preg_match('~^(\S+)\s+(\S+)(?:\s+\[([A-Za-z,]+)\])?$~D', $value, $cond)) { return false; }
			$flags = isset($cond[3]) ? explode(',', strtolower($cond[3])) : [];
			if (array_diff($flags, ['nc','nocase','or','ornext','nv','novary'])) { return false; }
			$orNext = in_array('or', $flags, true) || in_array('ornext', $flags, true);
			$isFalse = false;
			if ($cond[1] === '%{REQUEST_URI}') {
				$negated = str_starts_with($cond[2], '!');
				$pattern = $negated ? substr($cond[2], 1) : $cond[2];
				$result = self::literalPathMatch($pattern, $path, in_array('nc', $flags, true) || in_array('nocase', $flags, true));
				if ($result === null) { return false; }
				$isFalse = $result === $negated;
			} elseif ($cond[1] !== 'UNKNOWN' || $cond[2] !== 'UNKNOWN') {
				// The unfiltered native dump also reaches this classifier. Only
				// ordinary header reads and static comparisons are opaque-but-inert.
				// Lookaheads, subrequests, maps and expressions may do work even
				// before a later URI condition short-circuits the redirect.
				if (!preg_match('~^%\{(?:HTTP_HOST|HTTP:[A-Za-z0-9-]{1,64})\}$~D', $cond[1])
					|| strlen($cond[2]) > 256 || !preg_match('~^(?:!?\^[A-Za-z0-9_./\\\\^$|()*+!?:\[\]-]+|[<=>][0-9]+)$~D', $cond[2])) { return false; }
			}
			$groupFalse = $groupFalse && $isFalse;
			if (!$orNext) { $excluded = $excluded || $groupFalse; $groupFalse = true; }
		}
		return !$orNext && $excluded;
	}

	private static function serverRewriteUnrelated(string $value, array $conditions, array $paths): bool
	{
		// The native FreePBX ACME handler and hidden-file denial cannot touch
		// these routes unless one of the dispatch URIs actually selects them.
		if ($value === '(^\.|/\.) - [F]') {
			foreach ($paths as $path) { if (str_contains($path, '/.')) { return false; } }
			return true;
		}
		if (preg_match('~^(\S+)\s+-\s+\[H=text/plain,L\]$~D', $value, $rule)) {
			foreach ($paths as $path) { if (self::literalPathMatch($rule[1], $path) !== false) { return false; } }
			return true;
		}
		// Only an external redirect with a conventional stop flag qualifies
		// this way. Proxying, handler changes, chains and skip flags stay opaque.
		if (!$conditions || !preg_match('~^\^\s+(?:UNQUALIFIED_REMOTE_HANDLER|https?://[a-z0-9.-]+(?::[0-9]{1,5})?%\{REQUEST_URI\})\s+\[R=30[12378],L(?:,NE)?\]$~iD', $value)) { return false; }
		foreach ($paths as $path) { if (!self::conditionExcludes($conditions, $path)) { return false; } }
		return true;
	}

	private static function addHandlerQualified(string $value, array $paths): bool
	{
		$tokens = preg_split('/\s+/', $value);
		$handler = strtolower(array_shift($tokens));
		if (!$tokens || count($tokens) > 32 || !preg_match('~^[a-z][a-z0-9/+_.-]{0,127}$~D', $handler)) { return false; }
		$suffixes = [];
		foreach ($tokens as $token) {
			if (!preg_match('/^\.?([a-z0-9_-]{1,32})$/iD', $token, $match)) { return false; }
			$suffixes[] = strtolower($match[1]);
		}
		foreach ($paths as $path) {
			// API DirectoryIndex and media rewrite targets are included in $paths.
			// For other extensionless requests the served filename isn't proven.
			if (!str_contains(basename($path), '.') && !preg_match('#^/api/(?:sls-mass-notify|sipnotify)(?:/|$)#D', $path)) { return false; }
			foreach (explode('/', strtolower($path)) as $component) {
				// PATH_INFO and mod_mime's multi-extension handling both matter.
				$extensions = array_slice(explode('.', $component), 1);
				foreach (array_intersect($extensions, $suffixes) as $extension) {
					if ($handler !== 'application/x-httpd-php' || $extension !== 'php') { return false; }
				}
			}
		}
		return true;
	}

	private static function proxyRelevant(string $value, string $path): bool
	{
		if (preg_match('/^("[^"]+"|\S+)/D', $value, $match)) {
			$prefix = trim($match[1], "\"'");
			if (str_starts_with($prefix, '/') && strpbrk($prefix, '*?[') === false && !str_contains($prefix, '${') && !str_contains($prefix, '%{')) {
				return str_starts_with($path, $prefix);
			}
		}
		return true;
	}

	/** Apply Apache address specificity and first matching name before trusting a root. */
	private static function selectedRoute(array $records, string $host, int $port, string $address, array $known): ?int
	{
		$priority = -1; $candidates = [];
		foreach ($records as $index=>$record) {
			$rank = -1;
			foreach ($record['bindings'] as $binding) {
				if ($binding['port'] !== $port || !in_array($address, $binding['addresses'], true)) { continue; }
				$exact = $binding['key'] === ($address === '::1' ? '[::1]' : $address) . ':' . $port;
				$rank = max($rank, !empty($record['main']) ? 0 : ($exact ? 2 : 1));
			}
			if ($rank < 0 || $rank < $priority) { continue; }
			if ($rank > $priority) { $priority = $rank; $candidates = []; }
			$candidates[] = $index;
		}
		if (!$candidates) { return null; }
		// Native address precedence and row counts must agree before any name
		// can authorize credentials, including an explicitly configured name.
		$nativePriority = -1; $nativeRows = []; $bindingCount = 0;
		foreach ($known as $key=>$names) {
			$binding = self::binding($key);
			if (!$binding || $binding['port'] !== $port || !in_array($address, $binding['addresses'], true)) { continue; }
			$rank = $key === ($address === '::1' ? '[::1]' : $address) . ':' . $port ? 2 : 1;
			if ($rank < $nativePriority) { continue; }
			if ($rank > $nativePriority) { $nativePriority = $rank; $nativeRows = []; $bindingCount = 0; }
			$nativeRows = array_merge($nativeRows, $names); $bindingCount++;
		}
		if ($priority === 0) {
			if ($nativeRows) { return null; }
		} else {
			if ($bindingCount !== 1 || $nativePriority !== $priority || count($nativeRows) !== count($candidates)) { return null; }
			foreach ($candidates as $position => $index) {
				$primary = $records[$index]['primary_name'] ?? null;
				if ($primary !== null && $primary !== $nativeRows[$position]) { return null; }
			}
		}
		foreach ($candidates as $index) {
			// An earlier unnamed vhost may inherit this exact hostname, even
			// when a later vhost declares it explicitly. Its aliases alone do
			// not establish a primary name or let us skip native precedence.
			if (count($candidates) > 1 && !isset($records[$index]['primary_name'])) { return null; }
			if (!empty($records[$index]['names_inferred'])) { continue; }
			foreach ($records[$index]['names'] as $name) { if (fnmatch($name, $host)) { return $index; } }
			if (!empty($records[$index]['main']) && !$records[$index]['names'] && $host === '127.0.0.1') { return $index; }
		}
		// A genuinely nameless sole vhost serves any validated Host. Other
		// inferred names still need to match the requested hostname.
		if (count($candidates) === 1 && !empty($records[$candidates[0]]['names_inferred'])) {
			$matches = !empty($records[$candidates[0]]['implicit_name']);
			foreach ($records[$candidates[0]]['names'] as $name) { if (fnmatch($name, $host)) { $matches = true; break; } }
			if ($matches) { return $candidates[0]; }
		}
		return null;
	}

	private static function routeTargets($publicHost, $vhostDump, $configurationDump, string $path): array
	{
		$host = is_string($publicHost) ? strtolower(trim($publicHost)) : '';
		$hostPattern = '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D';
		if ($host !== '' && !preg_match($hostPattern, $host)) { throw new \RuntimeException('The configured PBX hostname cannot establish local route authority.'); }
		$vhosts = self::nativeInventory($vhostDump, 'SLS_LOCAL_WEB_VHOST_DUMP', 'DUMP_VHOSTS');
		$config = self::nativeInventory($configurationDump, 'SLS_LOCAL_WEB_CONFIG_DUMP', 'DUMP_CONFIG');
		$known = []; $currentBinding = null; $unclassifiedNativeBindings = false;
		foreach (explode("\n", $vhosts) as $line) {
			if (preg_match('/^\s*(\*|_default_|[0-9.]+|\[[0-9a-f:]+\]):([0-9]+)\s+([^\s(]+)/i', $line, $match)) {
				$currentBinding = self::binding($match[1] . ':' . $match[2]);
				if (!$currentBinding) { $unclassifiedNativeBindings = true; }
				elseif (strtolower($match[3]) !== 'is') { $known[$currentBinding['key']][] = strtolower($match[3]); }
			} elseif ($currentBinding && preg_match('/^\s+port\s+([0-9]+)\s+namevhost\s+([^\s(]+)/i', $line, $match)
				&& (int)$match[1] === $currentBinding['port']) { $known[$currentBinding['key']][] = strtolower($match[2]); }
			elseif (trim($line) === 'UNCLASSIFIED_VHOST_BINDING' || preg_match('/^\s*\S+:\S+\s+/', $line)) {
				$unclassifiedNativeBindings = true; $currentBinding = null;
			}
		}
		$main = ['names'=>[], 'name_declared'=>false, 'root'=>'', 'ssl'=>false, 'blocked'=>false, 'bindings'=>[]];
		$records = []; $record = null; $sections = []; $listeners = []; $unclassifiedBindings = false;
		$pendingConditions = []; $dispatchPaths = self::dispatchPaths($path);
		foreach (explode("\n", $config) as $source) {
			$line = trim($source);
			if ($line === '' || $line[0] === '#') { continue; }
			if (preg_match('/^RewriteCond\s+(.+)$/iD', $line, $condition)) {
				$pendingConditions[] = $condition[1]; continue;
			}
			if ($pendingConditions && !$sections && !preg_match('/^RewriteRule\s/i', $line)) {
				// An intervening directive may interrupt an OR chain in the filtered
				// inventory. Discarding just its predecessor could make a redirect
				// appear excluded. Refuse this server when association is uncertain.
				if ($record === null) { $main['blocked'] = true; } else { $record['blocked'] = true; }
			}
			$conditions = $pendingConditions; $pendingConditions = [];
			if (preg_match('/^<VirtualHost\s+([^>]+)>$/iD', $line, $match)) {
				if ($record !== null) { throw new \RuntimeException('Nested Apache virtual hosts cannot establish route authority.'); }
				$record = ['names'=>[], 'name_declared'=>false, 'root'=>'', 'ssl'=>null, 'blocked'=>false, 'bindings'=>[]];
				foreach (preg_split('/\s+/', trim($match[1])) as $binding) {
					$value=self::binding($binding);
					if ($value) { $record['bindings'][]=$value; }
					else { $unclassifiedBindings = true; }
				}
				$sections=[]; continue;
			}
			if (preg_match('/^<\/VirtualHost>$/iD', $line)) { if ($record !== null) { $records[]=$record; } $record=null; $sections=[]; continue; }
			if (preg_match('/^<\/([A-Za-z]+)>$/D', $line)) { array_pop($sections); continue; }
			if (preg_match('/^<([A-Za-z]+)(?:\s+(.+))?>$/D', $line, $match)) { $sections[]=[strtolower($match[1]),trim($match[2]??'', "\"'")]; continue; }
			if (!preg_match('/^([A-Za-z][A-Za-z0-9]*)\s+(.+)$/D', $line, $match)) { continue; }
			$name=strtolower($match[1]); $value=trim($match[2]); $target=&$main; if ($record !== null) { $target=&$record; }
			if ($name==='listen' && $record===null) { $binding=self::binding(preg_split('/\s+/', $value)[0]); if ($binding) { $listeners[]=$binding; } }
			elseif ($name==='servername' || $name==='serveralias') {
				$target['name_declared']=true;
				foreach (preg_split('/\s+/', $value) as $candidate) {
					$candidate=strtolower(trim($candidate,"\"'")); $candidate=preg_replace('#^[a-z]+://#','',$candidate); $candidate=preg_replace('/:[0-9]+$/','',$candidate);
					if (preg_match('/^[a-z0-9*?.-]{1,253}$/D',$candidate)) {
						$target['names'][]=$candidate;
						if ($name==='servername') { $target['primary_name']=$candidate; }
					}
				}
			} elseif ($name==='documentroot') { $target['root']=rtrim(trim($value,"\"'"),'/'); }
			elseif ($name==='sslengine') { $target['ssl']=strtolower($value)==='on'; }
			elseif (array_filter($dispatchPaths, static fn($uri) => self::routeRelevant($sections, $uri))) {
				if ($name==='proxypass' && !array_filter($dispatchPaths, static fn($uri) => self::proxyRelevant($value, $uri))) { continue; }
				if (!$sections && $name==='redirectmatch' && self::redirectMatchUnrelated($value, $dispatchPaths)) { continue; }
				if (!$sections && $name==='rewriterule' && self::serverRewriteUnrelated($value, $conditions, $dispatchPaths)) { continue; }
				if (str_contains($value,'UNQUALIFIED_REMOTE_HANDLER')) { $target['blocked']=true; }
				elseif ($name==='alias') {
					if (!preg_match('/^("[^"]+"|\S+)\s+("[^"]+"|\S+)$/D',$value,$alias)) { $target['blocked']=true; }
					else {
						$source = trim($alias[1], '"'); $destination = trim($alias[2], '"');
						$from = rtrim($source, '/');
						if (rtrim($destination, '/') !== '/var/www/html' . $from) {
							foreach ($dispatchPaths as $dispatchPath) {
								if ($from === '' || $dispatchPath === $from || str_starts_with($dispatchPath, $from . '/')) {
									if (!self::legacyDispatcher($source, $destination, $path)) { $target['blocked'] = true; }
									break;
								}
							}
						}
					}
				} elseif ($name==='addhandler') {
					if (!self::addHandlerQualified($value, $dispatchPaths)) { $target['blocked'] = true; }
				} elseif ($name==='sethandler') {
					$handler=trim($value,"\"'");
					if ($handler!=='application/x-httpd-php' && !preg_match('#^proxy:unix:/(?:run|var/run)/php/[A-Za-z0-9_.-]{1,128}\.sock\|fcgi://(?:localhost|127\.0\.0\.1|\[::1\])/?$#D',$handler)) { $target['blocked']=true; }
				} elseif (in_array($name,['proxypass','proxypassmatch','aliasmatch','scriptalias','redirect','redirectmatch','rewriterule'],true)) {
					// Only the publisher's fixed generated-media rewrite is known;
					// unrelated Directory/Location sections were excluded above.
					$knownMedia=$name==='rewriterule' && $sections === [['directory','/var/www/html/sls_mass_notify']]
						&& str_starts_with($path,'/sls_mass_notify/') && in_array($value,[
						'^assets/[A-Za-z0-9_.-]+\\.(?:png|jpg|svg|ico)$ - [END]',
						'^([A-Za-z0-9][A-Za-z0-9_.-]{0,179}\\.(?:png|xml))$ /api/sls-mass-notify/media.php?file=$1 [END,QSA]',
						'^ - [F,END]'],true);
					if (!$knownMedia) { $target['blocked']=true; }
				}
			}
			unset($target);
		}
		if ($record !== null) { throw new \RuntimeException('Incomplete Apache route inventory.'); }
		// Unknown bindings can outrank a named wildcard route as well. Do not
		// send credentials using an incomplete account of address precedence.
		if ($unclassifiedBindings || $unclassifiedNativeBindings) { return []; }
		$used=[];
		foreach ($records as &$item) {
			foreach ($item['bindings'] as $binding) { foreach ($binding['addresses'] as $address) { $used[$binding['port']][$address]=true; } }
			if ($item['root']==='') { $item['root']=$main['root']; }
			if ($item['ssl']===null) { $item['ssl']=$main['ssl']; }
			$item['blocked']=$item['blocked']||$main['blocked'];
		}
		unset($item);
		foreach ($listeners as $binding) {
			$available=array_values(array_filter($binding['addresses'],static fn($address)=>!isset($used[$binding['port']][$address])));
			if ($available) { $binding['addresses']=$available; $item=$main; $item['bindings']=[$binding]; $item['main']=true; $records[]=$item; }
		}
		foreach ($records as &$item) {
			if (!$item['names'] && empty($item['main'])) {
				$found=[]; foreach ($item['bindings'] as $binding) { foreach ($known[$binding['key']]??[] as $name) { $found[$name]=true; } }
				if (count($found)===1) {
					$item['names']=array_keys($found);
					$item['names_inferred']=true;
					// Unsupported address/port syntax may hide a more specific
					// competing vhost; it cannot prove this nameless exception.
					$item['implicit_name']=!$item['name_declared'] && !$main['name_declared']
						&& !$unclassifiedBindings && !$unclassifiedNativeBindings;
				}
			}
		}
		unset($item);
		$targets=[]; $ports=[];
		foreach ($records as $index=>$item) {
			if ($item['root']!=='/var/www/html' || $item['blocked']) { continue; }
			$names=$item['names'];
			$chosen=$host;
			if ($chosen==='') {
				foreach ($names as $name) { if (preg_match($hostPattern,$name)) { $chosen=$name; break; } }
				if ($chosen==='' && !empty($item['main']) && !$names) { $chosen='127.0.0.1'; }
			}
			$matches=($host==='' && !empty($item['main']) && !$names) || !empty($item['implicit_name']);
			foreach ($names as $name) { if (fnmatch($name,$chosen)) { $matches=true; break; } }
			if (!$matches || $chosen==='') { continue; }
			foreach ($item['bindings'] as $binding) {
				if (empty($item['main'])) {
					$native=$known[$binding['key']]??[];
					if (!$native || ($names && !array_intersect($native,$names))) { continue; }
				}
				$port=$binding['port']; $addresses=$binding['addresses'];
				if ($listeners) { $allowed=[]; foreach ($listeners as $listener) { if ($listener['port']===$port) { $allowed=array_merge($allowed,$listener['addresses']); } } $addresses=array_values(array_intersect($addresses,$allowed)); }
				foreach ($addresses as $address) {
					if (self::selectedRoute($records, $chosen, $port, $address, $known) !== $index) { continue; }
					$ports[$port]=true; if (count($ports)>16) { throw new \RuntimeException('More than sixteen actual PBX listeners require explicit route qualification.'); }
					$scheme=$item['ssl']?'https':'http'; $connectHost=$address==='::1'?'[::1]':$address;
					$key=$scheme.'://'.$chosen.':'.$port.'@'.$connectHost;
					$targets[$key]=['url'=>$scheme.'://'.$chosen.':'.$port,'connect_url'=>$scheme.'://'.$connectHost.':'.$port,
						'host'=>$chosen,'host_header'=>$chosen.(in_array($scheme.':'.$port,['http:80','https:443'],true)?'':':'.$port),
						'resolve'=>$chosen.':'.$port.':'.$connectHost,'host_matched'=>true,'route_authorized'=>true];
				}
			}
		}
		return array_values($targets);
	}

	private static function requestPath($path): string
	{
		if (!is_string($path) || !preg_match('#^/[A-Za-z0-9/_?&=.-]{1,511}$#D', $path)) {
			throw new \RuntimeException('Local Apache verification rejected an invalid probe path.');
		}
		$route = explode('?', $path, 2)[0];
		if (str_contains($route, '//') || preg_match('#(?:^|/)\.{1,2}(?:/|$)#D', $route)) {
			throw new \RuntimeException('Local Apache verification requires a canonical probe path.');
		}
		return $route;
	}

	public static function targets($publicHost, $vhostDump = null, $configurationDump = null, $path = '/api/sls-mass-notify/')
	{
		return self::routeTargets($publicHost, $vhostDump, $configurationDump, self::requestPath($path));
	}

	public static function responses($publicHost, $path, array $headers, $timeoutSeconds, $vhostDump = null, $configurationDump = null)
	{
			if ((!is_int($timeoutSeconds) && !is_float($timeoutSeconds)) || !is_finite((float)$timeoutSeconds) || $timeoutSeconds <= 0
				|| count($headers) > 32) { throw new \RuntimeException('Local Apache verification rejected invalid request bounds.'); }
		$route = self::requestPath($path);
			$requestHeaders = []; $sensitive = false;
		foreach ($headers as $header) {
				if (!is_string($header)) { throw new \RuntimeException('Local Apache verification rejected an invalid probe header.'); }
				$header = trim($header);
				if (!preg_match('/^[A-Za-z0-9-]{1,64}:[^\x00-\x08\x0a-\x1f\x7f]{0,8192}$/D', $header)) {
				throw new \RuntimeException('Local Apache verification rejected an invalid probe header.');
			}
				$name = strtolower(substr($header, 0, (int)strpos($header, ':')));
				if (!in_array($name, ['accept','cache-control'], true)) { $sensitive = true; }
			$requestHeaders[] = $header;
		}
		$deadline = hrtime(true) / 1000000000 + 25;
			$targets = self::routeTargets($publicHost,$vhostDump,$configurationDump,$route);
			if (!$targets && $sensitive) { throw new \RuntimeException('No independently qualified local PBX route matches this request. Credentials were not sent; run the root-assisted installation check.'); }

			foreach ($targets as $target) {
			$remaining = $deadline - hrtime(true) / 1000000000;
			if ($remaining <= 0) {
				break;
			}
			if (!function_exists('curl_init') || !defined('CURLOPT_CONNECT_TO')) { throw new \RuntimeException('Local verification requires the qualified PHP cURL extension.'); }
			$body = ''; $responseHeaders = []; $headerBytes = 0; $headerLines = 0; $overflow = false;
			$milliseconds = max(1, (int)floor(min($remaining, max(1, min(10, (float)$timeoutSeconds))) * 1000));
			$handle = curl_init($target['url'] . $path);
			if ($handle === false) { throw new \RuntimeException('Local verification could not initialize its bounded transport.'); }
			try {
				$connection = parse_url($target['connect_url']);
				$options = [
					CURLOPT_HTTPGET => true, CURLOPT_RETURNTRANSFER => false,
					CURLOPT_RESOLVE => [$target['resolve']],
					// Match any URL spelling at this port: cURL canonicalizes
					// numeric host aliases before applying named DNS overrides.
					CURLOPT_CONNECT_TO => [':' . $connection['port'] . ':' . $connection['host'] . ':' . $connection['port']],
					CURLOPT_HTTPHEADER => array_merge(['Host: ' . $target['host_header']], $requestHeaders, ['Connection: close']),
					CURLOPT_PROXY => '', CURLOPT_NOPROXY => '*',
					CURLOPT_FOLLOWLOCATION => false, CURLOPT_MAXREDIRS => 0,
					CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
					CURLOPT_CONNECTTIMEOUT_MS => $milliseconds, CURLOPT_TIMEOUT_MS => $milliseconds,
					CURLOPT_NOSIGNAL => true,
					// Self-signed PBX TLS is checked over the independently qualified
					// loopback destination. The URL retains its real Host and SNI.
					CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
					CURLOPT_HEADERFUNCTION => static function ($unused, $line) use (&$responseHeaders, &$headerBytes, &$headerLines, &$overflow, $deadline) {
						$headerBytes += strlen($line); $headerLines++;
						if ($headerBytes > 32768 || $headerLines > 100 || hrtime(true) / 1000000000 >= $deadline) { $overflow = true; return 0; }
						$responseHeaders[] = rtrim($line, "\r\n"); return strlen($line);
					},
					CURLOPT_WRITEFUNCTION => static function ($unused, $chunk) use (&$body, &$overflow, $deadline) {
						if (strlen($body) + strlen($chunk) > 262144 || hrtime(true) / 1000000000 >= $deadline) { $overflow = true; return 0; }
						$body .= $chunk; return strlen($chunk);
					},
				];
				if (!curl_setopt_array($handle, $options)) { throw new \RuntimeException('Local verification could not enforce its transport bounds.'); }
				$complete = curl_exec($handle);
				$status = $complete !== false && !$overflow && curl_errno($handle) === 0 ? (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE) : 0;
				if ($status === 0) { $responseHeaders = []; $body = ''; }
			} finally { curl_close($handle); }
			yield ['status' => $status, 'headers' => $responseHeaders, 'body' => $body];
		}
	}
}
