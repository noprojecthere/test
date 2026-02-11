<?php
// ============================================
// SKTECH LIVE - M3U PLAYLIST GENERATOR v3.0
// FIXES: Status detection, HTML filtering, Emoji encoding
// ============================================

error_reporting(E_ALL);
ini_set('display_errors', 1);

$CACHE_DIR = __DIR__ . '/../cache';
$OUTPUT_FILE = __DIR__ . '/../public/playlist.m3u';
$KEYS_CACHE = $CACHE_DIR . '/keys.json';
$TEMP_OUTPUT = __DIR__ . '/../public/playlist_temp.m3u';

if (!is_dir($CACHE_DIR)) mkdir($CACHE_DIR, 0755, true);
if (!is_dir(dirname($OUTPUT_FILE))) mkdir(dirname($OUTPUT_FILE), 0755, true);

// ============================================
// LOOKUP TABLE
// ============================================
$LOOKUP_TABLE_D = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
                  "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" .
                  " !\"#\$%&'()*+,-./" .
                  "0123456789:;<=>?" .
                  "@EGMNKABUVCDYHLI" .
                  "FPOZQSRWTXJ[\\]^_" .
                  "`egmnkabuvcdyhli" .
                  "fpozqsrwtxj{|}~\x7f";

// ============================================
// FUNCTIONS
// ============================================
function logMsg($msg) {
    echo "[" . date('H:i:s') . "] $msg\n";
}

function customToStandardBase64($customB64) {
    global $LOOKUP_TABLE_D;
    $result = '';
    $tableLen = strlen($LOOKUP_TABLE_D);
    for ($i = 0; $i < strlen($customB64); $i++) {
        $ascii = ord($customB64[$i]);
        $result .= ($ascii < $tableLen) ? $LOOKUP_TABLE_D[$ascii] : $customB64[$i];
    }
    return $result;
}

function decryptSKLive($encryptedData, $key, $iv) {
    if (empty($encryptedData)) return null;
    $standardB64 = customToStandardBase64($encryptedData);
    $decoded = base64_decode($standardB64, true);
    if ($decoded === false) return null;
    $reversed = strrev($decoded);
    $ciphertext = base64_decode($reversed, true);
    if ($ciphertext === false || strlen($ciphertext) % 16 !== 0) return null;
    $decrypted = openssl_decrypt($ciphertext, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $decrypted ?: null;
}

function fetchUrl($url, $timeout = 15) {
    $parts = parse_url($url);
    if (!$parts || !isset($parts['host'])) return ['body' => '', 'code' => 0];
    $path = $parts['path'] ?? '';
    $segments = explode('/', $path);
    $encodedSegments = array_map('rawurlencode', $segments);
    $encodedPath = implode('/', $encodedSegments);
    $scheme = $parts['scheme'] ?? 'https';
    $encodedUrl = $scheme . '://' . $parts['host'] . $encodedPath;
    if (isset($parts['query'])) $encodedUrl .= '?' . $parts['query'];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $encodedUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['body' => $response ?: '', 'code' => $httpCode];
}

// ============================================
// CHECK IF LINK IS VALID STREAM (NOT HTML)
// ============================================
function isValidStreamUrl($link) {
    $link = trim($link);
    if (empty($link)) return false;
    
    // HTML content detect karo
    if (preg_match('/<\s*(html|head|body|script|div|DOCTYPE)/i', $link)) return false;
    if (strpos($link, '<!DOCTYPE') !== false) return false;
    if (strpos($link, '<html') !== false) return false;
    if (strpos($link, '<script') !== false) return false;
    
    // Must start with http:// or https://
    if (!preg_match('#^https?://#i', $link)) return false;
    
    // Should not contain HTML tags
    if (strip_tags($link) !== $link) return false;
    
    // no.link skip karo
    if (strpos($link, 'no.link') !== false) return false;
    
    return true;
}

// ============================================
// TRY TO EXTRACT REAL URL FROM HTML
// ============================================
function extractStreamFromHtml($html) {
    // HTML mein se actual .m3u8 ya .mpd URL dhundho
    $patterns = [
        // playbackURL = "https://...m3u8..."
        '/playbackURL\s*=\s*["\']([^"\']+\.m3u8[^"\']*)/i',
        // source: "https://...m3u8..."
        '/source\s*[:=]\s*["\']([^"\']+\.m3u8[^"\']*)/i',
        // .mpd URLs
        '/playbackURL\s*=\s*["\']([^"\']+\.mpd[^"\']*)/i',
        '/source\s*[:=]\s*["\']([^"\']+\.mpd[^"\']*)/i',
        // Generic http m3u8
        '/(https?:\/\/[^\s"\'<>]+\.m3u8[^\s"\'<>]*)/i',
        // Generic http mpd
        '/(https?:\/\/[^\s"\'<>]+\.mpd[^\s"\'<>]*)/i',
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $html, $matches)) {
            $url = $matches[1];
            // Clean up escaped characters
            $url = str_replace(['\\/', '\\n', '\\r'], ['/', '', ''], $url);
            $url = trim($url);
            if (!empty($url) && filter_var($url, FILTER_VALIDATE_URL)) {
                return $url;
            }
        }
    }
    return null;
}

// ============================================
// EXTRACT KEYS FROM CS3
// ============================================
function extractKeysFromCS3($keysCache) {
    logMsg("CS3 file downloading...");
    $cs3Url = "https://raw.githubusercontent.com/NivinCNC/CNCVerse-Cloud-Stream-Extension/builds/SKTechProvider.cs3";
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $cs3Url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 60,
    ]);
    $cs3Data = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if (empty($cs3Data) || $httpCode !== 200) {
        logMsg("CS3 download FAIL! HTTP: $httpCode - Using cached keys");
        return loadCachedKeys($keysCache);
    }
    logMsg("CS3 downloaded: " . strlen($cs3Data) . " bytes");
    
    $tmpFile = tempnam(sys_get_temp_dir(), 'cs3_');
    file_put_contents($tmpFile, $cs3Data);
    $zip = new ZipArchive();
    $dexData = null;
    if ($zip->open($tmpFile) === TRUE) {
        $dexData = $zip->getFromName('classes.dex');
        $zip->close();
    }
    @unlink($tmpFile);
    
    if (empty($dexData)) {
        logMsg("DEX not found in ZIP - Using cached keys");
        return loadCachedKeys($keysCache);
    }
    logMsg("DEX size: " . strlen($dexData) . " bytes");
    
    $stringIdsSize = unpack('V', substr($dexData, 0x38, 4))[1];
    $stringIdsOff = unpack('V', substr($dexData, 0x3C, 4))[1];
    $hexStrings32 = [];
    $urlStrings = [];
    
    for ($i = 0; $i < $stringIdsSize; $i++) {
        $dataOff = unpack('V', substr($dexData, $stringIdsOff + ($i * 4), 4))[1];
        if ($dataOff >= strlen($dexData)) continue;
        $pos = $dataOff;
        $shift = 0; $strSize = 0;
        do {
            if ($pos >= strlen($dexData)) break;
            $b = ord($dexData[$pos]); $strSize |= ($b & 0x7F) << $shift; $shift += 7; $pos++;
        } while ($b & 0x80);
        
        $str = ''; $count = 0;
        while ($pos < strlen($dexData) && ord($dexData[$pos]) != 0 && $count < 2000) {
            $str .= $dexData[$pos]; $pos++; $count++;
        }
        
        if (strlen($str) == 32 && ctype_xdigit($str)) $hexStrings32[] = $str;
        if (preg_match('#^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/?$#', $str)) $urlStrings[] = rtrim($str, '/');
    }
    
    logMsg("Found " . count($hexStrings32) . " hex strings, " . count($urlStrings) . " URLs");
    if (count($hexStrings32) < 2) {
        logMsg("Not enough hex strings - Using cached keys");
        return loadCachedKeys($keysCache);
    }
    
    $baseUrl = "https://sufyanpromax.space";
    foreach ($urlStrings as $url) {
        if (strpos($url, 'github') !== false || strpos($url, 'google') !== false || 
            strpos($url, 'android') !== false || strpos($url, 'cloudstream') !== false) continue;
        $baseUrl = $url;
        logMsg("Base URL from CS3: $baseUrl");
        break;
    }
    
    $result = [
        'key' => $hexStrings32[0],
        'iv' => $hexStrings32[1],
        'base_url' => $baseUrl,
        'extracted_at' => date('Y-m-d H:i:s'),
    ];
    file_put_contents($keysCache, json_encode($result, JSON_PRETTY_PRINT));
    logMsg("Keys cached!");
    
    return ['key' => hex2bin($hexStrings32[0]), 'iv' => hex2bin($hexStrings32[1]), 'base_url' => $baseUrl];
}

function loadCachedKeys($keysCache) {
    if (!file_exists($keysCache)) { logMsg("NO CACHED KEYS!"); return null; }
    $cached = json_decode(file_get_contents($keysCache), true);
    if (!$cached || empty($cached['key'])) { logMsg("Cached keys CORRUPT!"); return null; }
    logMsg("Using CACHED keys from: " . ($cached['extracted_at'] ?? 'unknown'));
    return ['key' => hex2bin($cached['key']), 'iv' => hex2bin($cached['iv']), 'base_url' => $cached['base_url'] ?? 'https://sufyanpromax.space'];
}

// ============================================
// EVENT STATUS - FIXED VERSION
// Uses timestamp from event data properly
// ============================================
function getEventStatus($event) {
    $now = time();
    
    // === METHOD 1: Direct status field ===
    $status = strtolower(trim($event['status'] ?? ''));
    if (in_array($status, ['live', 'started', 'inprogress', 'in_progress'])) return 'live';
    if (in_array($status, ['ended', 'finished', 'completed', 'closed'])) return 'ended';
    if (in_array($status, ['upcoming', 'scheduled', 'notstarted', 'not_started'])) return 'upcoming';
    
    // === METHOD 2: isLive boolean ===
    if (isset($event['isLive'])) {
        if ($event['isLive'] === true || $event['isLive'] === 1 || $event['isLive'] === '1' || $event['isLive'] === 'true') {
            return 'live';
        }
    }
    
    // === METHOD 3: Timestamp based ===
    $startTime = null;
    $endTime = null;
    
    // Try multiple possible field names for start time
    $startFields = ['eventTime', 'startTime', 'timestamp', 'matchTime', 'time', 'start', 'scheduledTime'];
    foreach ($startFields as $field) {
        if (!empty($event[$field])) {
            $val = $event[$field];
            if (is_numeric($val)) {
                $ts = (int)$val;
                // Check if milliseconds (13+ digits)
                if ($ts > 9999999999) $ts = (int)($ts / 1000);
                $startTime = $ts;
            } else {
                $ts = strtotime($val);
                if ($ts !== false) $startTime = $ts;
            }
            if ($startTime) break;
        }
    }
    
    // Try end time
    $endFields = ['endTime', 'end', 'finishTime'];
    foreach ($endFields as $field) {
        if (!empty($event[$field])) {
            $val = $event[$field];
            if (is_numeric($val)) {
                $ts = (int)$val;
                if ($ts > 9999999999) $ts = (int)($ts / 1000);
                $endTime = $ts;
            } else {
                $ts = strtotime($val);
                if ($ts !== false) $endTime = $ts;
            }
            if ($endTime) break;
        }
    }
    
    if ($startTime) {
        logMsg("  Time debug: start=" . date('Y-m-d H:i', $startTime) . " now=" . date('Y-m-d H:i', $now) . " diff=" . round(($now - $startTime)/60) . "min");
        
        if ($endTime) {
            if ($now < $startTime) return 'upcoming';
            if ($now >= $startTime && $now <= $endTime) return 'live';
            if ($now > $endTime) return 'ended';
        } else {
            // No end time - sports events ~3 hours for football, ~8 hours for cricket
            $category = strtolower($event['category'] ?? '');
            if (strpos($category, 'cricket') !== false) {
                $duration = 8 * 3600; // 8 hours for cricket
            } elseif (strpos($category, 'basketball') !== false || strpos($category, 'nba') !== false) {
                $duration = 3 * 3600; // 3 hours
            } elseif (strpos($category, 'tennis') !== false) {
                $duration = 5 * 3600; // 5 hours
            } else {
                $duration = 3 * 3600; // 3 hours default (football etc)
            }
            
            $assumedEnd = $startTime + $duration;
            
            if ($now < $startTime) return 'upcoming';
            if ($now >= $startTime && $now <= $assumedEnd) return 'live';
            if ($now > $assumedEnd) return 'ended';
        }
    }
    
    // === METHOD 4: Check eventName for clues ===
    $eventName = strtolower($event['eventName'] ?? '');
    if (strpos($eventName, 'live') !== false) return 'live';
    
    // === DEFAULT: If we have no time info, assume live (stream exists) ===
    return 'live';
}

// ============================================
// MAIN EXECUTION
// ============================================
logMsg("========================================");
logMsg("SKTech Live M3U Generator v3.0");
logMsg("========================================");

// Step 1: Keys
$keys = extractKeysFromCS3($KEYS_CACHE);
if (!$keys) { logMsg("FATAL: No keys!"); exit(1); }
$AES_KEY = $keys['key'];
$AES_IV = $keys['iv'];
$BASE_URL = $keys['base_url'];
logMsg("Key: " . bin2hex($AES_KEY));
logMsg("IV: " . bin2hex($AES_IV));
logMsg("Base: $BASE_URL");

// Step 2: Events
logMsg("Fetching events...");
$eventsResult = fetchUrl("$BASE_URL/events.txt", 30);
if (empty($eventsResult['body']) || $eventsResult['code'] !== 200) {
    logMsg("FATAL: Events fetch fail! HTTP: " . $eventsResult['code']);
    exit(1);
}
logMsg("Events: " . strlen($eventsResult['body']) . " bytes");

$decryptedEvents = decryptSKLive(trim($eventsResult['body']), $AES_KEY, $AES_IV);
if (!$decryptedEvents) { logMsg("FATAL: Events decrypt fail!"); exit(1); }

$eventWrappers = json_decode($decryptedEvents, true);
if (!$eventWrappers) { logMsg("FATAL: Events JSON fail!"); exit(1); }
logMsg("Total events: " . count($eventWrappers));

// Step 3: Process all events
$allChannels = [];
$stats = ['processed' => 0, 'failed' => 0, 'html_extracted' => 0, 'html_skipped' => 0, 'nolink_skipped' => 0];

foreach ($eventWrappers as $wrapper) {
    $eventJson = $wrapper['event'] ?? null;
    if (!$eventJson) continue;
    $event = json_decode($eventJson, true);
    if (!$event) continue;
    if (isset($event['visible']) && !$event['visible']) continue;
    
    $eventName = $event['eventName'] ?? 'Unknown';
    $teamA = $event['teamAName'] ?? '';
    $teamB = $event['teamBName'] ?? '';
    $category = trim($event['category'] ?? 'Other');
    $logo = $event['eventLogo'] ?? '';
    $links = $event['links'] ?? '';
    if (empty($links)) continue;
    
    // Display name
    if (!empty($teamA) && !empty($teamB) && $teamA !== $teamB) {
        $displayName = "$teamA vs $teamB";
    } elseif (!empty($teamA)) {
        $displayName = $teamA;
    } else {
        $displayName = $eventName;
    }
    
    // Status detect
    $status = getEventStatus($event);
    logMsg("Event: $displayName → Status: $status");
    
    // Fetch streams
    $fullStreamUrl = "$BASE_URL/$links";
    $streamResult = fetchUrl($fullStreamUrl);
    if ($streamResult['code'] != 200 || empty($streamResult['body'])) {
        logMsg("  SKIP: HTTP " . $streamResult['code']);
        $stats['failed']++;
        continue;
    }
    
    $decryptedStreams = decryptSKLive(trim($streamResult['body']), $AES_KEY, $AES_IV);
    if (!$decryptedStreams) { $stats['failed']++; continue; }
    
    $streams = json_decode($decryptedStreams, true);
    if (!$streams || !is_array($streams)) { $stats['failed']++; continue; }
    
    logMsg("  Streams: " . count($streams));
    
    $serverNum = 1;
    foreach ($streams as $stream) {
        $serverName = $stream['name'] ?? "Server $serverNum";
        $link = $stream['link'] ?? '';
        $apiKey = $stream['api'] ?? '';
        
        // TokenApi try
        if (empty($link) && !empty($stream['tokenApi'])) {
            $tokenConfig = json_decode($stream['tokenApi'], true);
            if ($tokenConfig && !empty($tokenConfig['api'])) {
                $tokenResult = fetchUrl($tokenConfig['api']);
                if ($tokenResult['code'] == 200 && !empty($tokenResult['body'])) {
                    if (!empty($tokenConfig['link_key'])) {
                        $tokenJson = json_decode($tokenResult['body'], true);
                        if ($tokenJson) $link = $tokenJson[$tokenConfig['link_key']] ?? '';
                    }
                    if (empty($link)) $link = trim($tokenResult['body']);
                }
            }
        }
        
        if (empty($link)) { $serverNum++; continue; }
        
        // Split link|headers
        $linkParts = explode('|', $link, 2);
        $streamUrl = trim($linkParts[0]);
        $headers = $linkParts[1] ?? '';
        
        // ============================================
        // CRITICAL FIX: Check if URL is HTML content
        // ============================================
        if (!isValidStreamUrl($streamUrl)) {
            // Try to extract actual stream URL from HTML
            $extractedUrl = extractStreamFromHtml($streamUrl);
            if ($extractedUrl) {
                logMsg("  HTML→Extracted: $serverName → " . substr($extractedUrl, 0, 80));
                $streamUrl = $extractedUrl;
                $stats['html_extracted']++;
            } else {
                logMsg("  SKIP HTML: $serverName (no stream URL found in HTML)");
                $stats['html_skipped']++;
                $serverNum++;
                continue;
            }
        }
        
        // Skip no.link URLs
        if (strpos($streamUrl, 'no.link') !== false) {
            logMsg("  SKIP: $serverName → no.link");
            $stats['nolink_skipped']++;
            $serverNum++;
            continue;
        }
        
        // Add to channels
        if (!isset($allChannels[$category])) $allChannels[$category] = [];
        
        $allChannels[$category][] = [
            'display_name' => $displayName,
            'server_name' => $serverName,
            'logo' => $logo,
            'category' => $category,
            'url' => $streamUrl,
            'headers' => $headers,
            'api' => $apiKey,
            'status' => $status,
            'status_order' => ($status === 'live' ? 0 : ($status === 'upcoming' ? 1 : 2)),
        ];
        
        $stats['processed']++;
        $serverNum++;
    }
}

logMsg("========================================");
logMsg("Stats: processed={$stats['processed']} failed={$stats['failed']} html_extracted={$stats['html_extracted']} html_skipped={$stats['html_skipped']} nolink_skipped={$stats['nolink_skipped']}");

// ============================================
// Step 4: SORT - Groups alphabetical, within group: live > upcoming > ended
// ============================================
ksort($allChannels);
foreach ($allChannels as $group => &$channels) {
    usort($channels, function($a, $b) {
        if ($a['status_order'] !== $b['status_order']) return $a['status_order'] - $b['status_order'];
        return strcmp($a['display_name'], $b['display_name']);
    });
}
unset($channels);

// ============================================
// Step 5: Generate M3U with PROPER UTF-8 emojis
// ============================================
// UTF-8 Emojis - defined as proper bytes
$EMOJI_LIVE = "\xF0\x9F\x94\xB4";      // 🔴
$EMOJI_UPCOMING = "\xE2\x8F\xB0";       // ⏰
$EMOJI_ENDED = "\xE2\x9D\x8C";          // ❌
$EMOJI_TV = "\xF0\x9F\x93\xBA";         // 📺

$m3u = "#EXTM3U\n";
$m3u .= "# SKTech Live - Generated: " . date('Y-m-d H:i:s T') . "\n";
$m3u .= "# Auto-updated every 13 minutes via GitHub Actions\n\n";

$totalStreams = 0;
$liveCount = 0;
$upcomingCount = 0;
$endedCount = 0;

foreach ($allChannels as $group => $channels) {
    $m3u .= "# ======================================\n";
    $m3u .= "# $EMOJI_TV $group\n";
    $m3u .= "# ======================================\n\n";
    
    foreach ($channels as $ch) {
        // Emoji based on status
        switch ($ch['status']) {
            case 'live':
                $emoji = $EMOJI_LIVE;
                $liveCount++;
                break;
            case 'upcoming':
                $emoji = $EMOJI_UPCOMING;
                $upcomingCount++;
                break;
            case 'ended':
                $emoji = $EMOJI_ENDED;
                $endedCount++;
                break;
            default:
                $emoji = $EMOJI_LIVE;
                $liveCount++;
        }
        
        $fullName = "$emoji " . $ch['display_name'] . " - " . $ch['server_name'];
        
        // Clean logo URL
        $logo = str_replace('"', '', $ch['logo']);
        $cat = str_replace('"', '', $ch['category']);
        
        $m3u .= "#EXTINF:-1 tvg-logo=\"{$logo}\" group-title=\"{$cat}\",{$fullName}\n";
        
        // Headers
        if (!empty($ch['headers'])) {
            $headerPairs = explode('&', $ch['headers']);
            foreach ($headerPairs as $pair) {
                $kv = explode('=', $pair, 2);
                if (count($kv) == 2) {
                    $hName = strtolower(trim($kv[0]));
                    $hVal = trim($kv[1]);
                    if ($hName === 'user-agent') $m3u .= "#EXTVLCOPT:http-user-agent={$hVal}\n";
                    elseif ($hName === 'referer' || $hName === 'referrer') $m3u .= "#EXTVLCOPT:http-referrer={$hVal}\n";
                    elseif ($hName === 'origin') $m3u .= "#EXTVLCOPT:http-origin={$hVal}\n";
                }
            }
        }
        
        // DRM license
        if (!empty($ch['api']) && strpos($ch['url'], '.mpd') !== false) {
            $m3u .= "#KODIPROP:inputstream.adaptive.license_key={$ch['api']}\n";
        }
        
        $m3u .= "{$ch['url']}\n\n";
        $totalStreams++;
    }
}

$m3u .= "# ======================================\n";
$m3u .= "# $EMOJI_LIVE Live: $liveCount | $EMOJI_UPCOMING Upcoming: $upcomingCount | $EMOJI_ENDED Ended: $endedCount\n";
$m3u .= "# Total streams: {$totalStreams}\n";
$m3u .= "# Generated: " . date('Y-m-d H:i:s T') . "\n";
$m3u .= "# ======================================\n";

// ============================================
// Step 6: Validate and Save
// ============================================
if ($totalStreams === 0) {
    logMsg("WARNING: 0 streams! NOT saving.");
    exit(1);
}

logMsg("$EMOJI_LIVE Live: $liveCount | $EMOJI_UPCOMING Upcoming: $upcomingCount | $EMOJI_ENDED Ended: $endedCount");
logMsg("Total valid streams: $totalStreams");

// Write temp
file_put_contents($TEMP_OUTPUT, $m3u);

// Validate
$tempContent = file_get_contents($TEMP_OUTPUT);
if (strpos($tempContent, '#EXTM3U') === 0 && $totalStreams > 0) {
    // Check against old file
    if (file_exists($OUTPUT_FILE)) {
        $oldSize = filesize($OUTPUT_FILE);
        $newSize = strlen($m3u);
        if ($oldSize > 0 && $newSize < ($oldSize * 0.1)) {
            logMsg("WARNING: New file 90%+ smaller! Old=$oldSize New=$newSize");
        }
    }
    rename($TEMP_OUTPUT, $OUTPUT_FILE);
    logMsg("SUCCESS! playlist.m3u updated - $totalStreams streams");
} else {
    logMsg("VALIDATION FAILED!");
    @unlink($TEMP_OUTPUT);
    exit(1);
}

logMsg("Done! Time: " . round(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 2) . "s");
exit(0);
?>
