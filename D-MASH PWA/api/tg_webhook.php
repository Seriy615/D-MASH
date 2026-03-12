<?php
// D-MASH BOT WEBHOOK - AUTO BINDING
declare(strict_types=1);

define('TG_BOT_TOKEN', '8564655749:AAEI-sHz13gJPzY_-bN9bN4wlWBs6Gqidjo');
define('DB_PATH', __DIR__ . '/../../shadow_data/relay_vault.db');

$content = file_get_contents("php://input");
$update = json_decode($content, true);

if (!$update || !isset($update["message"])) exit;

$chat_id = (string)$update["message"]["chat"]["id"];
$text = $update["message"]["text"] ?? "";

try {
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Если пацан пришел по ссылке /start [hash]
    if (preg_match('/\/start ([a-f0-9]{64})/', $text, $matches)) {
        $hash = $matches[1];
        
        $stmt = $db->prepare("INSERT OR REPLACE INTO tg_notif (h, tg_id) VALUES (?, ?)");
        $stmt->execute([$hash, $chat_id]);

        send_tg_msg($chat_id, "✅ Ксива принята! Телега привязана к хешу: " . substr($hash, 0, 8) . "...");
    } else {
        // Если просто зашел поздороваться
        send_tg_msg($chat_id, "🤝 Здорово! Твой Chat ID: $chat_id\n\nЧтобы привязать уведомления, делай это через настройки в калькуляторе D-MASH.");
    }

} catch (Exception $e) {
    file_put_contents("tg_error.log", $e->getMessage());
}

function send_tg_msg($chat_id, $text) {
    $url = "https://api.telegram.org/bot" . TG_BOT_TOKEN . "/sendMessage?chat_id=$chat_id&text=" . urlencode($text);
    @file_get_contents($url);
}