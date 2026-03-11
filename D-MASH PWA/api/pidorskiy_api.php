<?php
// D-MASH SILENT V3.8 - INSTANT NOTIFY + BLINKING MODE
declare(strict_types=1);

define('TG_BOT_TOKEN', '8564655749:AAEI-sHz13gJPzY_-bN9bN4wlWBs6Gqidjo');
define('DB_PATH', __DIR__ . '/../../shadow_data/relay_vault.db');

// --- РАСШИРЯЕМ ДОПУСКИ ---
ini_set('memory_limit', '512M');
ini_set('post_max_size', '100M');
ini_set('upload_max_filesize', '100M');
ini_set('max_execution_time', '300');

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, X-DMASH-AGENT");
header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");

if (($_SERVER['HTTP_X_DMASH_AGENT'] ?? '') !== 'V1Silent-Node') {
    http_response_code(404); exit;
}

try {
    if (!file_exists(dirname(DB_PATH))) mkdir(dirname(DB_PATH), 0750, true);
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA journal_mode = WAL;");

    // Таблицы
    $db->exec("CREATE TABLE IF NOT EXISTS spool (id INTEGER PRIMARY KEY, r_hash TEXT, s_pub TEXT, sig TEXT, blob TEXT, ts INTEGER, is_voip INTEGER DEFAULT 0)");
    $db->exec("CREATE TABLE IF NOT EXISTS tg_notif (h TEXT PRIMARY KEY, tg_id TEXT, last_msg_id INTEGER DEFAULT NULL)");
    $db->exec("CREATE TABLE IF NOT EXISTS online_status (h TEXT PRIMARY KEY, last_seen INTEGER)");
    $db->exec("CREATE TABLE IF NOT EXISTS voip_cooldown (h TEXT PRIMARY KEY, last_call INTEGER)");

    // Чистка
    if (random_int(1, 100) <= 10) {
        $expiration = time() - 36000; 
        $db->prepare("DELETE FROM spool WHERE ts < ?")->execute([$expiration]);
        $db->prepare("DELETE FROM online_status WHERE last_seen < ?")->execute([time() - 3600]);
    }

    $method = $_SERVER['REQUEST_METHOD'];

    if ($method === 'POST') {
        $raw = file_get_contents('php://input');
        $input = json_decode($raw, true);

        // 1. БАТЧ-ПРОСТУК
        if (isset($input['check_batch'])) {
            $hashes = $input['hashes'] ?? [];
            if (empty($hashes)) { echo json_encode([]); exit; }
            $placeholders = implode(',', array_fill(0, count($hashes), '?'));
            $stmt = $db->prepare("SELECT r_hash, SUM(CASE WHEN is_voip = 0 THEN 1 ELSE 0 END) as msgs, SUM(CASE WHEN is_voip = 1 THEN 1 ELSE 0 END) as calls FROM spool WHERE r_hash IN ($placeholders) GROUP BY r_hash");
            $stmt->execute($hashes);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            exit;
        }

        // 2. ПРИВЯЗКА ТЕЛЕГРАМА
        if (isset($input['set_tg'], $input['h'], $input['tg_id'])) {
            $stmt = $db->prepare("INSERT OR REPLACE INTO tg_notif (h, tg_id) VALUES (?, ?)");
            $stmt->execute([$input['h'], $input['tg_id']]);
            echo json_encode(["status" => "ok"]); exit;
        }

        // 3. ЗАГРУЗКА ПАКЕТА (PUSH)
        if (isset($input['blob'])) {
            $msg_bytes = hex2bin($input['blob']);
            $sig_bytes = hex2bin($input['sig']);
            $pub_bytes = hex2bin($input['s_pub']);
            if (!sodium_crypto_sign_verify_detached($sig_bytes, $msg_bytes, $pub_bytes)) {
                throw new Exception("Invalid PUSH signature", 403);
            }

            $is_voip = (isset($input['is_voip']) && $input['is_voip'] === true) ? 1 : 0;
            
            $stmt = $db->prepare("INSERT INTO spool (r_hash, s_pub, sig, blob, ts, is_voip) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$input['r_hash'], $input['s_pub'], $input['sig'], $input['blob'], time(), $is_voip]);
            
            // ЛОГИКА МГНОВЕННОГО УВЕДОМЛЕНИЯ
            $stmt = $db->prepare("SELECT tg_id, last_msg_id FROM tg_notif WHERE h = ?");
            $stmt->execute([$input['r_hash']]);
            $tg = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($tg) {
                $stmt_on = $db->prepare("SELECT last_seen FROM online_status WHERE h = ?");
                $stmt_on->execute([$input['r_hash']]);
                $last_seen = (int)$stmt_on->fetchColumn();

                // 1. Проверяем, надо ли вообще шуметь
                $is_silent = isset($input['silent']) && $input['silent'] === true;
                
                // Если юзер в оффлайне (> 7 сек) и пакет не технический
                if (time() - $last_seen > 7 && !$is_silent) {
                    
                    // 2. ЖЕСТКАЯ ЗАЧИСТКА: Удаляем ЛЮБОЕ старое уведомление (хоть звонок, хоть маляву)
                    if (!empty($tg['last_msg_id'])) {
                        tg_api("deleteMessage", [
                            "chat_id" => $tg['tg_id'], 
                            "message_id" => $tg['last_msg_id']
                        ]);
                    }

                    // 3. Текст малявы
                    $txt = $is_voip ? "📞 D-MASH: Входящий базар!" : "🔔 D-MASH: Новая малява!";
                    
                    // 4. Шлем новый маяк
                    $res = tg_api("sendMessage", [
                        "chat_id" => $tg['tg_id'], 
                        "text" => $txt
                    ]);
                    
                    // 5. Запоминаем ID нового сообщения, чтоб в следующий раз его грохнуть
                    if ($res && isset($res['result']['message_id'])) {
                        $db->prepare("UPDATE tg_notif SET last_msg_id = ? WHERE h = ?")
                           ->execute([$res['result']['message_id'], $input['r_hash']]);
                    } else {
                        // Если отправить не вышло, обнуляем ID в базе
                        $db->prepare("UPDATE tg_notif SET last_msg_id = NULL WHERE h = ?")
                           ->execute([$input['r_hash']]);
                    }
                }
            }
            echo json_encode(["status" => "ok"]); exit;
        }

    } elseif ($method === 'GET') {
        // --- 4. ЗАБОР ПАКЕТОВ (PULL) ---
        $s_pub_hex = $_GET['pub'] ?? '';
        $ts_str = $_GET['ts'] ?? '';
        $sig_hex = $_GET['sig'] ?? '';
        $my_hash = $_GET['h'] ?? '';

        if (empty($s_pub_hex) || empty($ts_str) || empty($sig_hex) || empty($my_hash)) {
            throw new Exception("Auth required", 401);
        }
        
        if (abs(time() - (int)$ts_str) > 300) {
            throw new Exception("Timestamp expired", 403);
        }

        $pub_bytes = hex2bin($s_pub_hex);
        $msg_to_verify = $pub_bytes . $ts_str;
        $sig_bytes = hex2bin($sig_hex);

        if (!$sig_bytes || !$pub_bytes || !sodium_crypto_sign_verify_detached($sig_bytes, $msg_to_verify, $pub_bytes)) {
            throw new Exception("Invalid PULL signature", 403);
        }

        // ОБНОВЛЯЕМ ОНЛАЙН
        $db->prepare("INSERT OR REPLACE INTO online_status (h, last_seen) VALUES (?, ?)")->execute([$my_hash, time()]);

        // ЧИСТИМ ТЕЛЕГУ
        $stmt = $db->prepare("SELECT tg_id, last_msg_id FROM tg_notif WHERE h = ?");
        $stmt->execute([$my_hash]);
        $tg = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($tg && $tg['last_msg_id']) {
            tg_api("deleteMessage", ["chat_id" => $tg['tg_id'], "message_id" => $tg['last_msg_id']]);
            $db->prepare("UPDATE tg_notif SET last_msg_id = NULL WHERE h = ?")->execute([$my_hash]);
        }

        // Выдача маляв
        $stmt = $db->prepare("SELECT id, s_pub, sig, blob FROM spool WHERE r_hash = ? ORDER BY ts ASC");
        $stmt->execute([$my_hash]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if (!empty($rows)) {
            $ids = array_column($rows, 'id');
            $db->prepare("DELETE FROM spool WHERE id IN (".implode(',', array_fill(0, count($ids), '?')).")")->execute($ids);
        }
        echo json_encode($rows);
    }
} catch (Exception $e) { http_response_code(500); echo json_encode(["error" => $e->getMessage()]); }

function tg_api($m, $p) {
    $url = "https://api.telegram.org/bot" . TG_BOT_TOKEN . "/" . $m;
    $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($p)); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3); $r = curl_exec($ch); curl_close($ch); return json_decode($r, true);
}