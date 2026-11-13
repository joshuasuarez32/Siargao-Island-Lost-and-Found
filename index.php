<?php
session_start();
require_once 'db.php';

// Generate CSRF token if not present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ================= BACKEND AJAX REQUEST HANDLER =================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    $headers = getallheaders();
    $tokenFromHeader = $headers['X-CSRF-Token'] ?? ($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $tokenFromHeader)) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token (CSRF verification failed).']);
        exit;
    }

    $action = $_POST['action'];

    try {
        if ($action === 'report_lost' || $action === 'report_found') {
            $itemType = ($action === 'report_found') ? 'found' : 'lost';
            $category = trim($_POST['category'] ?? '');
            $title = trim($_POST['title'] ?? '');
            $details = trim($_POST['details'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $address = trim($_POST['address'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $locName = trim($_POST['location_name'] ?? '');
            $locAddr = trim($_POST['location_address'] ?? '');
            $lat = filter_var($_POST['latitude'] ?? null, FILTER_VALIDATE_FLOAT);
            $lng = filter_var($_POST['longitude'] ?? null, FILTER_VALIDATE_FLOAT);
            $imageData = $_POST['image_data'] ?? null;
            $lostItemId = filter_var($_POST['lost_item_id'] ?? null, FILTER_VALIDATE_INT) ?: null;

            if (empty($category) || empty($title) || empty($details) || empty($name) || empty($phone)) {
                throw new Exception('Please fill in all required fields.');
            }

            $managementCode = 'SF-' . strtoupper(bin2hex(random_bytes(4)));

            $insertColumns = 'item_type, category, title, details, reporter_name, address, phone, email, location_name, location_address, latitude, longitude, image_data, management_code, status';
            $insertValues = '?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'active\'';
            $insertParams = [$itemType, $category, $title, $details, $name, $address, $phone, $email, $locName, $locAddr, $lat, $lng, $imageData, $managementCode];
            $itemColumnNames = $pdo->query('SHOW COLUMNS FROM items')->fetchAll(PDO::FETCH_COLUMN, 0);
            if (in_array('lost_item_id', $itemColumnNames, true)) {
                $insertColumns .= ', lost_item_id';
                $insertValues .= ', ?';
                $insertParams[] = $lostItemId;
            }

            $stmt = $pdo->prepare("INSERT INTO items ({$insertColumns}) VALUES ({$insertValues})");
            $stmt->execute($insertParams);
            
            $insertId = $pdo->lastInsertId();
            $stmtFetch = $pdo->prepare("SELECT * FROM items WHERE id = ?");
            $stmtFetch->execute([$insertId]);
            $newItem = $stmtFetch->fetch();

            echo json_encode([
                'success' => true, 
                'management_code' => $managementCode,
                'item' => [
                    'id' => (int)$newItem['id'],
                    'title' => $newItem['title'],
                    'category' => $newItem['category'],
                    'name' => $newItem['reporter_name'],
                    'phone' => $newItem['phone'],
                    'email' => $newItem['email'],
                    'date' => date('M j, Y', strtotime($newItem['created_at'])),
                    'time' => date('h:i A', strtotime($newItem['created_at'])),
                    'details' => $newItem['details'],
                    'image' => $newItem['image_data'],
                    'location' => ['name' => $newItem['location_name'], 'address' => $newItem['location_address']],
                    'managementCode' => $newItem['management_code'],
                    'status' => $newItem['status'],
                    'lost_item_id' => $newItem['lost_item_id'] ?? null,
                    'claims' => []
                ]
            ]);
            exit;
        }

        if ($action === 'submit_recovery_request') {
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            $finderName = trim($_POST['finder_name'] ?? '');
            $finderPhone = trim($_POST['finder_phone'] ?? '');
            $finderEmail = trim($_POST['finder_email'] ?? '');
            $locationFound = trim($_POST['location_found'] ?? '');
            $foundAtInput = trim($_POST['found_at'] ?? '');
            $additionalDetails = trim($_POST['additional_details'] ?? '');
            $confirmation = $_POST['confirmation'] ?? '';

            if (!$itemId || $itemId < 1) {
                throw new Exception('This lost item could not be identified. Please reopen its report and try again.');
            }
            if ($finderName === '' || strlen($finderName) > 150 || $finderPhone === '' || strlen($finderPhone) > 40) {
                throw new Exception('Enter your name and a valid contact number.');
            }
            if (!preg_match('/^[0-9+().\-\s]{5,40}$/', $finderPhone)) {
                throw new Exception('Enter a valid contact number.');
            }
            if ($finderEmail !== '' && (strlen($finderEmail) > 254 || !filter_var($finderEmail, FILTER_VALIDATE_EMAIL))) {
                throw new Exception('Enter a valid email address or leave the field blank.');
            }
            if ($locationFound === '' || strlen($locationFound) > 255) {
                throw new Exception('Enter where you found the item.');
            }
            if ($additionalDetails === '' || strlen($additionalDetails) > 5000) {
                throw new Exception('Add details about where and how the item was found.');
            }
            if ($confirmation !== 'yes') {
                throw new Exception('Please confirm that the owner may use your contact details to follow up.');
            }

            $foundAt = DateTime::createFromFormat('Y-m-d\\TH:i', $foundAtInput);
            $dateErrors = DateTime::getLastErrors();
            if (!$foundAt || ($dateErrors !== false && ($dateErrors['warning_count'] > 0 || $dateErrors['error_count'] > 0))) {
                throw new Exception('Enter a valid date and time when you found the item.');
            }

            $itemStmt = $pdo->prepare("SELECT id FROM items WHERE id = ? AND item_type = 'lost'");
            $itemStmt->execute([$itemId]);
            if (!$itemStmt->fetchColumn()) {
                throw new Exception('This lost item is no longer available for recovery requests.');
            }

            $evidenceImagePath = null;
            $savedEvidenceAbsolutePath = null;
            if (isset($_FILES['evidence_image']) && $_FILES['evidence_image']['error'] !== UPLOAD_ERR_NO_FILE) {
                $upload = $_FILES['evidence_image'];
                if ($upload['error'] !== UPLOAD_ERR_OK) {
                    throw new Exception('The photograph could not be uploaded. Please try again.');
                }
                if ($upload['size'] > 5 * 1024 * 1024) {
                    throw new Exception('The photograph must be 5 MB or smaller.');
                }

                $mimeType = (new finfo(FILEINFO_MIME_TYPE))->file($upload['tmp_name']);
                $allowedImageTypes = [
                    'image/jpeg' => 'jpg',
                    'image/png' => 'png',
                    'image/webp' => 'webp',
                    'image/gif' => 'gif'
                ];
                if (!isset($allowedImageTypes[$mimeType])) {
                    throw new Exception('Upload a JPG, PNG, WEBP, or GIF photograph.');
                }

                $uploadDirectory = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'recovery_requests';
                if (!is_dir($uploadDirectory) && !mkdir($uploadDirectory, 0755, true) && !is_dir($uploadDirectory)) {
                    throw new Exception('The evidence upload folder could not be prepared.');
                }
                $imageFileName = bin2hex(random_bytes(16)) . '.' . $allowedImageTypes[$mimeType];
                $savedEvidenceAbsolutePath = $uploadDirectory . DIRECTORY_SEPARATOR . $imageFileName;
                if (!move_uploaded_file($upload['tmp_name'], $savedEvidenceAbsolutePath)) {
                    throw new Exception('The photograph could not be saved. Please try again.');
                }
                $evidenceImagePath = 'uploads/recovery_requests/' . $imageFileName;
            }

            $requestStmt = $pdo->prepare("INSERT INTO recovery_requests (lost_item_id, finder_name, finder_phone, finder_email, location_found, found_at, additional_details, evidence_image_path, confirmation_accepted, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'New Request')");
            try {
                $requestStmt->execute([
                    $itemId,
                    $finderName,
                    $finderPhone,
                    $finderEmail !== '' ? $finderEmail : null,
                    $locationFound,
                    $foundAt->format('Y-m-d H:i:s'),
                    $additionalDetails,
                    $evidenceImagePath
                ]);
            } catch (Throwable $insertError) {
                if ($savedEvidenceAbsolutePath && is_file($savedEvidenceAbsolutePath)) {
                    @unlink($savedEvidenceAbsolutePath);
                }
                throw $insertError;
            }

            echo json_encode([
                'success' => true,
                'request_id' => (int)$pdo->lastInsertId(),
                'message' => 'Your recovery request has been sent to the item owner for review.'
            ]);
            exit;
        }

        if ($action === 'submit_claim') {
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            $fullName = trim($_POST['full_name'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            $contactPref = trim($_POST['contact_pref'] ?? 'phone');
            
            // Detailed verification answers
            $qBrand = trim($_POST['q_brand'] ?? '');
            $qColor = trim($_POST['q_color'] ?? '');
            $qSecondaryColor = trim($_POST['q_secondary_color'] ?? '');
            $qSize = trim($_POST['q_size'] ?? '');
            $qDamage = trim($_POST['q_damage'] ?? '');
            $qUniqueMarks = trim($_POST['q_unique_marks'] ?? '');
            $qAccessories = trim($_POST['q_accessories'] ?? '');
            $qContents = trim($_POST['q_contents'] ?? '');
            $qSpecificDetail = trim($_POST['q_specific_detail'] ?? '');
            
            // Loss info
            $lossLocation = trim($_POST['loss_location'] ?? '');
            $lossDate = trim($_POST['loss_date'] ?? '');
            $lossActivity = trim($_POST['loss_activity'] ?? '');
            $lossLastRemembered = trim($_POST['loss_last_remembered'] ?? '');
            $lossCircumstances = trim($_POST['loss_circumstances'] ?? '');
            
            // Evidence
            $proofImg = trim($_POST['proof_img'] ?? '');

            if (!$itemId || empty($fullName) || empty($phone)) {
                throw new Exception('Required claim fields (Name, Phone) must be completed.');
            }

            // Store verification details as JSON or text payload if columns exist, or adapt to existing schema
            $verificationDataJSON = json_encode([
                'brand' => $qBrand,
                'color' => $qColor,
                'secondary_color' => $qSecondaryColor,
                'size' => $qSize,
                'damage' => $qDamage,
                'unique_marks' => $qUniqueMarks,
                'accessories' => $qAccessories,
                'contents' => $qContents,
                'specific_detail' => $qSpecificDetail,
                'loss_location' => $lossLocation,
                'loss_date' => $lossDate,
                'loss_activity' => $lossActivity,
                'loss_last_remembered' => $lossLastRemembered,
                'loss_circumstances' => $lossCircumstances,
                'contact_pref' => $contactPref
            ]);

            // Reusing existing claims table structure with verification payload inside reason/verification column
            $stmt = $pdo->prepare("INSERT INTO claims (item_id, full_name, email, phone, reason, proof_img, status) VALUES (?, ?, ?, ?, ?, ?, 'Pending Verification')");
            $stmt->execute([$itemId, $fullName, $email, $phone, $verificationDataJSON, $proofImg]);
            
            echo json_encode(['success' => true, 'message' => 'Detailed verification claim submitted successfully.']);
            exit;
        }

        if ($action === 'manage_lookup') {
            $code = trim($_POST['management_code'] ?? '');
            if (empty($code)) {
                throw new Exception('Please enter a valid management code.');
            }

            $stmt = $pdo->prepare("SELECT * FROM items WHERE management_code = ?");
            $stmt->execute([$code]);
            $item = $stmt->fetch();

            if ($item) {
                $_SESSION['verified_mgmt_' . $item['id']] = true;

                $claimStmt = $pdo->prepare("SELECT * FROM claims WHERE item_id = ? ORDER BY created_at DESC");
                $claimStmt->execute([$item['id']]);
                $claims = $claimStmt->fetchAll();

                $recoveryRequests = [];
                $unreadRecoveryCount = 0;
                if ($item['item_type'] === 'lost') {
                    $recoveryStmt = $pdo->prepare("SELECT id, finder_name, location_found, found_at, status, created_at, owner_viewed_at FROM recovery_requests WHERE lost_item_id = ? ORDER BY created_at DESC");
                    $recoveryStmt->execute([$item['id']]);
                    foreach ($recoveryStmt->fetchAll(PDO::FETCH_ASSOC) as $recoveryRequest) {
                        $isUnread = empty($recoveryRequest['owner_viewed_at']);
                        if ($isUnread) $unreadRecoveryCount++;
                        $recoveryRequests[] = [
                            'id' => (int)$recoveryRequest['id'],
                            'finder_name' => $recoveryRequest['finder_name'],
                            'location_found' => $recoveryRequest['location_found'],
                            'found_at' => date('M j, Y · g:i A', strtotime($recoveryRequest['found_at'])),
                            'submitted_at' => date('M j, Y', strtotime($recoveryRequest['created_at'])),
                            'status' => $recoveryRequest['status'],
                            'unread' => $isUnread
                        ];
                    }
                }

                echo json_encode([
                    'success' => true, 
                    'item' => [
                        'id' => (int)$item['id'],
                        'item_type' => $item['item_type'],
                        'title' => $item['title'],
                        'category' => $item['category'],
                        'name' => $item['reporter_name'],
                        'phone' => $item['phone'],
                        'email' => $item['email'],
                        'date' => date('M j, Y', strtotime($item['created_at'])),
                        'details' => $item['details'],
                        'image' => $item['image_data'],
                        'location' => ['name' => $item['location_name'], 'address' => $item['location_address']],
                        'managementCode' => $item['management_code'],
                        'status' => $item['status'],
                        'claims' => $claims
                    ],
                    'recovery_requests' => $recoveryRequests,
                    'unread_recovery_count' => $unreadRecoveryCount
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid management code. Please verify and try again.']);
            }
            exit;
        }

        if ($action === 'get_recovery_request') {
            $requestId = filter_var($_POST['request_id'] ?? 0, FILTER_VALIDATE_INT);
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            if (!$requestId || !$itemId || empty($_SESSION['verified_mgmt_' . $itemId])) {
                throw new Exception('Unauthorized. Enter the private management code for this lost report first.');
            }

            $requestStmt = $pdo->prepare("SELECT r.*, i.title AS item_title FROM recovery_requests r INNER JOIN items i ON i.id = r.lost_item_id WHERE r.id = ? AND r.lost_item_id = ? AND i.item_type = 'lost'");
            $requestStmt->execute([$requestId, $itemId]);
            $recoveryRequest = $requestStmt->fetch(PDO::FETCH_ASSOC);
            if (!$recoveryRequest) {
                throw new Exception('This recovery request could not be found for the selected report.');
            }

            $viewedStmt = $pdo->prepare("UPDATE recovery_requests SET owner_viewed_at = COALESCE(owner_viewed_at, NOW()) WHERE id = ? AND lost_item_id = ?");
            $viewedStmt->execute([$requestId, $itemId]);
            $unreadStmt = $pdo->prepare("SELECT COUNT(*) FROM recovery_requests WHERE lost_item_id = ? AND owner_viewed_at IS NULL");
            $unreadStmt->execute([$itemId]);

            $evidenceData = null;
            $evidenceMime = null;
            $storedEvidencePath = $recoveryRequest['evidence_image_path'] ?? '';
            if (preg_match('#^uploads/recovery_requests/([a-f0-9]{32}\.(?:jpg|png|webp|gif))$#', $storedEvidencePath, $pathMatch)) {
                $evidenceAbsolutePath = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'recovery_requests' . DIRECTORY_SEPARATOR . $pathMatch[1];
                if (is_file($evidenceAbsolutePath) && filesize($evidenceAbsolutePath) <= 5 * 1024 * 1024) {
                    $evidenceMime = (new finfo(FILEINFO_MIME_TYPE))->file($evidenceAbsolutePath);
                    $evidenceData = 'data:' . $evidenceMime . ';base64,' . base64_encode(file_get_contents($evidenceAbsolutePath));
                }
            }

            echo json_encode([
                'success' => true,
                'unread_recovery_count' => (int)$unreadStmt->fetchColumn(),
                'request' => [
                    'id' => (int)$recoveryRequest['id'],
                    'item_id' => (int)$recoveryRequest['lost_item_id'],
                    'item_title' => $recoveryRequest['item_title'],
                    'finder_name' => $recoveryRequest['finder_name'],
                    'finder_phone' => $recoveryRequest['finder_phone'],
                    'finder_email' => $recoveryRequest['finder_email'],
                    'location_found' => $recoveryRequest['location_found'],
                    'found_at' => date('M j, Y · g:i A', strtotime($recoveryRequest['found_at'])),
                    'additional_details' => $recoveryRequest['additional_details'],
                    'evidence_image' => $evidenceData,
                    'evidence_mime' => $evidenceMime,
                    'confirmation_accepted' => (bool)$recoveryRequest['confirmation_accepted'],
                    'status' => $recoveryRequest['status'],
                    'submitted_at' => date('M j, Y · g:i A', strtotime($recoveryRequest['created_at']))
                ]
            ]);
            exit;
        }

        if ($action === 'update_recovery_status') {
            $requestId = filter_var($_POST['request_id'] ?? 0, FILTER_VALIDATE_INT);
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            $status = trim($_POST['status'] ?? '');
            $allowedRecoveryStatuses = ['New Request', 'Under Review', 'Contact Established', 'Verification in Progress', 'Successfully Returned', 'Rejected'];

            if (!$requestId || !$itemId || empty($_SESSION['verified_mgmt_' . $itemId])) {
                throw new Exception('Unauthorized. Enter the private management code for this lost report first.');
            }
            if (!in_array($status, $allowedRecoveryStatuses, true)) {
                throw new Exception('Select a valid recovery request status.');
            }

            $requestExists = $pdo->prepare("SELECT id FROM recovery_requests WHERE id = ? AND lost_item_id = ?");
            $requestExists->execute([$requestId, $itemId]);
            if (!$requestExists->fetchColumn()) {
                throw new Exception('This recovery request does not belong to the selected report.');
            }

            $updateStmt = $pdo->prepare("UPDATE recovery_requests SET status = ? WHERE id = ? AND lost_item_id = ?");
            $updateStmt->execute([$status, $requestId, $itemId]);
            $unreadStmt = $pdo->prepare("SELECT COUNT(*) FROM recovery_requests WHERE lost_item_id = ? AND owner_viewed_at IS NULL");
            $unreadStmt->execute([$itemId]);
            echo json_encode(['success' => true, 'unread_recovery_count' => (int)$unreadStmt->fetchColumn()]);
            exit;
        }

        if ($action === 'update_claim') {
            $claimId = filter_var($_POST['claim_id'] ?? 0, FILTER_VALIDATE_INT);
            $status = $_POST['status'] ?? 'Pending Verification';
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            $adminNotes = trim($_POST['admin_notes'] ?? '');
            $rejectionReason = trim($_POST['rejection_reason'] ?? '');

            $allowedStatuses = ['Pending Verification', 'Additional Information Required', 'Approved', 'Rejected'];
            if (!in_array($status, $allowedStatuses)) {
                throw new Exception('Invalid status transition.');
            }

            if ($status === 'Rejected' && empty($rejectionReason)) {
                throw new Exception('A reason is required when rejecting a claim.');
            }

            if (empty($_SESSION['verified_mgmt_' . $itemId])) {
                throw new Exception('Unauthorized action. Please re-authenticate with your management code.');
            }

            $stmt = $pdo->prepare("UPDATE claims SET status = ? WHERE id = ? AND item_id = ?");
            $stmt->execute([$status, $claimId, $itemId]);

            if ($status === 'Approved') {
                $itemStmt = $pdo->prepare("UPDATE items SET status = 'in_progress' WHERE id = ?");
                $itemStmt->execute([$itemId]);
            }

            echo json_encode(['success' => true]);
            exit;
        }

        if ($action === 'mark_returned') {
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);

            if (empty($_SESSION['verified_mgmt_' . $itemId])) {
                throw new Exception('Unauthorized action. Please re-authenticate with your management code.');
            }

            $stmt = $pdo->prepare("UPDATE items SET status = 'returned' WHERE id = ?");
            $stmt->execute([$itemId]);

            echo json_encode(['success' => true]);
            exit;
        }

        if ($action === 'delete_returned_found') {
            $itemId = filter_var($_POST['item_id'] ?? 0, FILTER_VALIDATE_INT);
            if (!$itemId || empty($_SESSION['verified_mgmt_' . $itemId])) {
                throw new Exception('Unauthorized action. Please re-authenticate with your management code.');
            }

            $itemStmt = $pdo->prepare('SELECT item_type, status FROM items WHERE id = ?');
            $itemStmt->execute([$itemId]);
            $item = $itemStmt->fetch(PDO::FETCH_ASSOC);
            if (!$item || $item['item_type'] !== 'found' || $item['status'] !== 'returned') {
                throw new Exception('Only a found item marked as returned can be removed.');
            }

            $pdo->beginTransaction();
            try {
                $claimStmt = $pdo->prepare('DELETE FROM claims WHERE item_id = ?');
                $claimStmt->execute([$itemId]);
                $deleteStmt = $pdo->prepare("DELETE FROM items WHERE id = ? AND item_type = 'found' AND status = 'returned'");
                $deleteStmt->execute([$itemId]);
                if ($deleteStmt->rowCount() !== 1) {
                    throw new Exception('This returned found item could not be removed.');
                }
                $pdo->commit();
            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $e;
            }

            unset($_SESSION['verified_mgmt_' . $itemId]);
            echo json_encode(['success' => true, 'message' => 'The returned item and its claims have been removed.']);
            exit;
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit;
    }
}

// ================= FETCH INITIAL DATA FROM MYSQL =================
$lostItemsPHP = [];
$foundItemsPHP = [];

try {
    $lStmt = $pdo->query("SELECT * FROM items WHERE item_type = 'lost' ORDER BY created_at DESC");
    while ($row = $lStmt->fetch()) {
        $lostItemsPHP[] = [
            'id' => (int)$row['id'],
            'title' => $row['title'],
            'category' => $row['category'],
            'name' => $row['reporter_name'],
            'details' => $row['details'],
            'date' => date('M j, Y', strtotime($row['created_at'])),
            'time' => date('h:i A', strtotime($row['created_at'])),
            'image' => $row['image_data'],
            'location' => ['name' => $row['location_name'], 'address' => $row['location_address']],
            'status' => $row['status']
        ];
    }

    $fStmt = $pdo->query("SELECT * FROM items WHERE item_type = 'found' ORDER BY created_at DESC");
    $foundRows = $fStmt->fetchAll();
    
    if (!empty($foundRows)) {
        $foundIds = array_column($foundRows, 'id');
        $placeholders = implode(',', array_fill(0, count($foundIds), '?'));
        
        $cStmt = $pdo->prepare("SELECT * FROM claims WHERE item_id IN ($placeholders) ORDER BY created_at DESC");
        $cStmt->execute($foundIds);
        $allClaims = $cStmt->fetchAll();
        
        $claimsByItem = [];
        foreach ($allClaims as $claim) {
            $claimsByItem[$claim['item_id']][] = $claim;
        }

        foreach ($foundRows as $row) {
            $foundItemsPHP[] = [
                'id' => (int)$row['id'],
                'title' => $row['title'],
                'category' => $row['category'],
                'name' => $row['reporter_name'],
                'phone' => $row['phone'],
                'email' => $row['email'],
                'date' => date('M j, Y', strtotime($row['created_at'])),
                'details' => $row['details'],
                'image' => $row['image_data'],
                'location' => ['name' => $row['location_name'], 'address' => $row['location_address']],
                'managementCode' => $row['management_code'],
                'status' => $row['status'],
                'lost_item_id' => $row['lost_item_id'] ?? null,
                'claims' => $claimsByItem[$row['id']] ?? []
            ];
        }
    }
} catch (Exception $e) {
    // Graceful fallback
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="<?php echo $_SESSION['csrf_token']; ?>">
  <title>Siargao Lost & Found — Island Community Recovery Platform</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Playfair+Display:ital,wght@0,600;0,700;1,600&display=swap" rel="stylesheet">

  <style>
    /* ================= DESIGN SYSTEM & VARIABLES ================= */
    :root {
      --primary-lost: #D92525;
      --primary-lost-hover: #B71C1C;
      --primary-lost-light: #FDF2F2;
      --primary-found: #00A94F;
      --primary-found-hover: #00863E;
      --primary-found-light: #F0FDF4;
      --bg-main: #FAFAFA;
      --bg-card: #FFFFFF;
      --text-main: #1A1D1E;
      --text-muted: #64748B;
      --text-light: #94A3B8;
      --border-color: #E2E8F0;
      --border-focus: #0F172A;
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 20px;
      --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0, 0, 0, 0.02);
      --shadow-md: 0 10px 25px -5px rgba(0, 0, 0, 0.07), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
      --shadow-lg: 0 20px 35px -10px rgba(0, 0, 0, 0.12), 0 10px 15px -5px rgba(0, 0, 0, 0.04);
      --transition-fast: 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      --transition-smooth: 0.35s cubic-bezier(0.16, 1, 0.3, 1);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Plus Jakarta Sans', sans-serif;
      color: var(--text-main);
      background: linear-gradient(-45deg, #FAFAFA, #F0FDF4, #F0F9FF, #FFFDF5);
      background-size: 400% 400%;
      animation: slowBG 28s ease infinite;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      overflow-x: hidden;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
      position: relative;
    }

    @keyframes slowBG {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }

    a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
      outline: 2px solid var(--border-focus);
      outline-offset: 2px;
    }

    /* ================= SMOOTH ANIMATION SYSTEM ================= */
    .page {
      display: none;
      opacity: 0;
      transform: translateY(10px);
      transition: opacity var(--transition-smooth), transform var(--transition-smooth);
      width: 100%;
      flex: 1;
      position: relative;
      z-index: 1;
    }

    .page.active-page {
      display: block;
      opacity: 1;
      transform: translateY(0);
    }

    @keyframes cardFadeIn {
      from { opacity: 0; transform: translateY(12px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    .item-card {
      animation: cardFadeIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      display: flex;
      flex-direction: column;
      background-color: var(--bg-card);
      border-radius: var(--radius-md);
      border: 1px solid var(--border-color);
      overflow: hidden;
      box-shadow: var(--shadow-sm);
      transition: transform var(--transition-fast), box-shadow var(--transition-fast), border-color var(--transition-fast);
    }

    .item-card:hover {
      transform: translateY(-5px);
      box-shadow: var(--shadow-md);
      border-color: #CBD5E1;
    }

    button, .action-card, nav a {
      transition: transform var(--transition-fast), background-color var(--transition-fast), color var(--transition-fast), box-shadow var(--transition-fast);
    }

    button:active, .action-card:active {
      transform: scale(0.98) !important;
    }

    .modal-overlay {
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background-color: rgba(15, 23, 42, 0.6);
      display: flex; justify-content: center; align-items: center;
      z-index: 1000; opacity: 0; visibility: hidden;
      transition: opacity var(--transition-smooth), visibility var(--transition-smooth);
      backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); padding: 20px;
    }

    .modal-overlay.active {
      opacity: 1;
      visibility: visible;
    }

    .modal-card {
      background-color: #FFFFFF;
      border-radius: var(--radius-lg);
      width: 100%;
      max-width: 440px;
      padding: 36px;
      text-align: center;
      box-shadow: var(--shadow-lg);
      position: relative;
      transform: scale(0.92) translateY(12px);
      transition: transform var(--transition-smooth);
    }

    .modal-overlay.active .modal-card {
      transform: scale(1) translateY(0);
    }

    .claim-modal-card { max-width: 820px; text-align: left; padding: 40px; max-height: 90vh; overflow-y: auto; }

    @media (prefers-reduced-motion: reduce) {
      *, ::before, ::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
    }

    .bg-decorations {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      pointer-events: none; z-index: 0; overflow: hidden;
    }

    .bg-shape { position: absolute; pointer-events: none; opacity: 0.12; }
    .palm-leaf-1 { top: 8%; left: -30px; width: 140px; height: 140px; animation: floatSlow 12s ease-in-out infinite alternate; }
    .palm-leaf-2 { top: 55%; right: -20px; width: 160px; height: 160px; animation: floatSlow 15s ease-in-out infinite alternate-reverse; }
    .bg-bubble-1 { top: 25%; right: 12%; width: 90px; height: 90px; background: radial-gradient(circle, rgba(0,169,79,0.18) 0%, rgba(255,255,255,0) 70%); border-radius: 50%; animation: floatSlow 10s ease-in-out infinite alternate; }
    .bg-bubble-2 { bottom: 18%; left: 10%; width: 120px; height: 120px; background: radial-gradient(circle, rgba(0,169,220,0.18) 0%, rgba(255,255,255,0) 70%); border-radius: 50%; animation: floatSlow 14s ease-in-out infinite alternate-reverse; }

    @keyframes floatSlow {
      0% { transform: translateY(0px) rotate(0deg); }
      100% { transform: translateY(-16px) rotate(4deg); }
    }

    header {
      display: flex; justify-content: space-between; align-items: center;
      padding: 18px 48px; background-color: rgba(255, 255, 255, 0.9);
      backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color); position: sticky; top: 0; z-index: 100;
      box-shadow: 0 4px 20px rgba(0,0,0,0.03);
    }

    .logo {
      display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 20px;
      text-decoration: none; color: var(--text-main); cursor: pointer; letter-spacing: -0.02em;
    }
    .logo .red-text { color: var(--primary-lost); }
    .logo .green-text { color: var(--primary-found); }
    .logo-icon {
      width: 24px; height: 24px; border: 2.5px solid var(--primary-lost); border-radius: 50%;
      position: relative; margin-left: 2px; display: inline-block;
    }
    .logo:hover .logo-icon { transform: rotate(15deg); border-color: var(--primary-found); }
    .logo-icon::after {
      content: ''; position: absolute; width: 8px; height: 2.5px; background: var(--primary-lost);
      bottom: -3px; right: -5px; transform: rotate(45deg);
    }
    .logo:hover .logo-icon::after { background: var(--primary-found); }

    nav ul { display: flex; list-style: none; align-items: center; gap: 8px; }
    nav a {
      text-decoration: none; color: var(--text-muted); font-size: 14px; font-weight: 600;
      padding: 8px 16px; border-radius: var(--radius-sm); cursor: pointer;
    }
    nav a:hover:not(.active) { background-color: #F1F5F9; color: var(--text-main); }
    nav a.active { background-color: var(--primary-lost); color: #FFFFFF; box-shadow: 0 2px 8px rgba(217, 37, 37, 0.3); }
    nav a#foundNav.active, nav a#reportFoundNav.active, nav a#manageNav.active {
      background-color: var(--primary-found); box-shadow: 0 2px 8px rgba(0, 169, 79, 0.3);
    }

    .hero-container {
      position: relative; width: 100%; min-height: calc(100vh - 80px);
      display: flex; flex-direction: column; justify-content: space-between; overflow: hidden; background: #00A9DC;
    }
    .hero-video-wrapper { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; overflow: hidden; }
    .hero-video-wrapper video { width: 100%; height: 100%; object-fit: cover; object-position: center bottom; }
    .hero-overlay {
      position: absolute; top: 0; left: 0; width: 100%; height: 100%;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.82) 0%, rgba(255, 255, 255, 0.55) 50%, rgba(255, 255, 255, 0.9) 100%);
      z-index: 1; pointer-events: none;
    }

    .home-main {
      display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 60px; padding: 60px 48px;
      align-items: center; max-width: 1240px; margin: 0 auto; width: 100%; min-height: calc(100vh - 180px);
      position: relative; z-index: 2;
    }
    .hero-left { display: flex; flex-direction: column; gap: 32px; }
    .hero-text h1 { font-family: 'Playfair Display', serif; font-size: 48px; font-weight: 700; line-height: 1.15; color: var(--text-main); margin-bottom: 14px; }
    .hero-text p { font-size: 16px; font-weight: 500; color: #334155; max-width: 480px; }

    .image-collage { position: relative; height: 250px; width: 100%; margin-top: 10px; }
    .collage-img {
      position: absolute; border-radius: var(--radius-md); object-fit: cover; box-shadow: var(--shadow-md);
      border: 4px solid #FFFFFF; animation: slowPulseZoom 8s ease-in-out infinite alternate;
    }
    @keyframes slowPulseZoom {
      0% { transform: scale(1) translateY(0); }
      50% { transform: scale(1.02) translateY(-4px); }
      100% { transform: scale(1) translateY(0); }
    }
    .collage-img:hover { transform: scale(1.06) translateY(-8px) !important; z-index: 10 !important; box-shadow: var(--shadow-lg); }
    .img-1 { width: 160px; height: 160px; bottom: 0; left: 0; z-index: 1; transform: rotate(-3deg); }
    .img-2 { width: 175px; height: 175px; bottom: 20px; left: 125px; z-index: 2; transform: rotate(2deg); }
    .img-3 { width: 185px; height: 185px; top: 0; left: 270px; z-index: 3; transform: rotate(-2deg); }

    .hero-right { display: flex; flex-direction: column; gap: 20px; justify-content: center; }
    .action-card {
      display: flex; justify-content: space-between; align-items: center; padding: 32px 38px;
      border-radius: var(--radius-md); text-decoration: none; cursor: pointer;
      box-shadow: var(--shadow-sm); border: 1px solid rgba(255, 255, 255, 0.6); position: relative; overflow: hidden;
      backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
    }
    .action-card:hover { transform: translateY(-5px) scale(1.01); box-shadow: var(--shadow-lg); }
    .action-card-content span { display: block; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; opacity: 0.92; }
    .action-card h2 { font-family: 'Playfair Display', serif; font-size: 36px; font-weight: 700; color: #FFFFFF; line-height: 1.1; }
    .action-card.lost { background-color: rgba(217, 37, 37, 0.94); color: #FFFFFF; }
    .action-card.lost:hover { background-color: var(--primary-lost-hover); }
    .action-card.found { background-color: rgba(0, 169, 79, 0.94); color: #FFFFFF; }
    .action-card.found:hover { background-color: var(--primary-found-hover); }

    .card-icon {
      width: 58px; height: 58px; display: flex; align-items: center; justify-content: center;
      background: rgba(255, 255, 255, 0.18); border-radius: 50%; backdrop-filter: blur(6px);
    }
    .action-card:hover .card-icon { transform: translateX(4px) scale(1.08); background: rgba(255, 255, 255, 0.32); }
    .card-icon svg { width: 28px; height: 28px; }

    .hero-wave-container { width: 100%; overflow: hidden; line-height: 0; margin-top: -30px; pointer-events: none; position: relative; z-index: 2; }
    .hero-wave-svg { position: relative; display: block; width: calc(100% + 1.3px); height: 52px; }
    .wave-path { animation: waveMove 12s linear infinite alternate; fill: #FAFAFA; }
    @keyframes waveMove { 0% { transform: translateX(0); } 100% { transform: translateX(-40px); } }

    .gallery-container { max-width: 1240px; margin: 0 auto; padding: 40px 48px; }
    .banner-container { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); }
    .page-title-banner { display: flex; align-items: center; gap: 14px; }
    .page-title-banner h2 { font-family: 'Playfair Display', serif; font-size: 34px; font-weight: 700; color: var(--text-main); }
    .banner-badge { font-size: 11px; font-weight: 700; padding: 6px 14px; border-radius: 20px; text-transform: uppercase; letter-spacing: 0.06em; }
    .banner-badge.lost-badge { background-color: var(--primary-lost-light); color: var(--primary-lost); }
    .banner-badge.found-badge { background-color: var(--primary-found-light); color: var(--primary-found); }

    .filter-section {
      display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 16px; margin-bottom: 32px;
      background: var(--bg-card); padding: 18px 22px; border-radius: var(--radius-md); border: 1px solid var(--border-color); box-shadow: var(--shadow-sm);
    }
    .filter-group { display: flex; flex-direction: column; gap: 6px; }
    .filter-group label { font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .filter-group input, .filter-group select {
      width: 100%; padding: 10px 14px; font-size: 14px; font-weight: 500; font-family: inherit;
      border: 1px solid var(--border-color); border-radius: var(--radius-sm); background-color: #FFFFFF; color: var(--text-main); outline: none;
    }
    .filter-group input:focus, .filter-group select:focus { border-color: var(--border-focus); }

    .items-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 24px; margin-bottom: 32px; }

    .item-img-placeholder {
      width: 100%; height: 190px; background-color: #F8FAFC; display: flex; align-items: center; justify-content: center;
      color: var(--text-light); font-size: 13px; font-weight: 500; overflow: hidden; position: relative; border-bottom: 1px solid var(--border-color);
    }
    .item-img-placeholder img { width: 100%; height: 100%; object-fit: cover; transition: transform var(--transition-smooth); }
    .item-card:hover .item-img-placeholder img { transform: scale(1.04); }

    .item-body { padding: 20px; display: flex; flex-direction: column; flex: 1; }
    .item-category-badge {
      align-self: flex-start; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;
      padding: 3px 10px; background: #F1F5F9; color: var(--text-muted); border-radius: 6px; margin-bottom: 10px;
    }
    .item-title { font-size: 17px; font-weight: 700; color: var(--text-main); margin-bottom: 8px; text-transform: capitalize; line-height: 1.3; }
    .item-meta { font-size: 13px; color: var(--text-muted); line-height: 1.5; margin-bottom: 12px; }
    .item-location { font-size: 13px; color: var(--primary-lost); font-weight: 600; margin-bottom: 16px; display: flex; align-items: flex-start; gap: 6px; }
    .found-page-card .item-location { color: var(--primary-found); }

    .item-actions { margin-top: auto; padding-top: 14px; border-top: 1px solid #F1F5F9; display: flex; flex-direction: column; gap: 8px; }
    .btn-found-this, .btn-contact-claimer {
      background-color: var(--primary-found); color: #FFFFFF; border: none; padding: 10px 14px; font-size: 13px; font-weight: 700;
      cursor: pointer; border-radius: var(--radius-sm); width: 100%; text-align: center; box-shadow: 0 2px 6px rgba(0, 169, 79, 0.2);
    }
    .btn-contact-claimer { background-color: var(--primary-lost); box-shadow: 0 2px 6px rgba(217, 37, 37, 0.2); }
    .btn-found-this:hover { background-color: var(--primary-found-hover); transform: translateY(-1px); }
    .btn-contact-claimer:hover { background-color: var(--primary-lost-hover); transform: translateY(-1px); }
    .item-details-btn {
      background: transparent; border: 1px solid var(--border-color); color: var(--text-muted); font-size: 12px; font-weight: 600;
      padding: 8px; border-radius: var(--radius-sm); cursor: pointer; width: 100%; text-align: center;
    }
    .item-details-btn:hover { background: #F8FAFC; color: var(--text-main); border-color: #CBD5E1; }

    .pagination-container { display: flex; justify-content: center; align-items: center; gap: 8px; margin: 32px 0; }
    .pagination-btn {
      padding: 8px 14px; font-size: 13px; font-weight: 600; background: #FFFFFF; border: 1px solid var(--border-color);
      border-radius: var(--radius-sm); cursor: pointer; color: var(--text-main);
    }
    .pagination-btn.active { background: var(--text-main); color: #FFFFFF; border-color: var(--text-main); }
    .pagination-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .status-badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 6px; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em; }
    .status-in-progress { background-color: #FEF3C7; color: #B45309; }
    .status-returned { background-color: #F1F5F9; color: var(--text-muted); }

    .form-container { max-width: 1000px; margin: 0 auto; padding: 48px; }
    .form-header-title { font-family: 'Playfair Display', serif; font-size: 34px; font-weight: 700; margin-bottom: 8px; }
    .form-header-sub { color: var(--text-muted); font-size: 15px; margin-bottom: 36px; }

    .form-main {
      display: grid; grid-template-columns: 1fr 1fr; gap: 40px; background: var(--bg-card);
      padding: 40px; border-radius: var(--radius-lg); border: 1px solid var(--border-color); box-shadow: var(--shadow-sm); align-items: start;
    }
    .form-column { display: flex; flex-direction: column; gap: 2px; }
    .form-column h3 { font-size: 16px; font-weight: 700; margin-bottom: 18px; color: var(--text-main); padding-bottom: 10px; border-bottom: 1px solid var(--border-color); }

    .input-group { width: 100%; margin-bottom: 18px; }
    .input-group label { display: block; font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
    .input-group input, .input-group select, .input-group textarea {
      width: 100%; padding: 12px 16px; font-size: 14px; font-family: inherit; border: 1px solid var(--border-color);
      border-radius: var(--radius-sm); background-color: #FFFFFF; outline: none; color: var(--text-main);
    }
    .input-group input:focus, .input-group select:focus, .input-group textarea:focus { border-color: var(--border-focus); }

    .location-section { width: 100%; margin-top: 4px; }
    .location-search-wrap { position: relative; width: 100%; }
    .location-suggestions {
      position: absolute; top: calc(100% + 4px); left: 0; right: 0; background: #FFFFFF;
      border: 1px solid var(--border-color); border-radius: var(--radius-sm); box-shadow: var(--shadow-lg); z-index: 50; max-height: 200px; overflow-y: auto; display: none;
    }
    .location-suggestions.active { display: block; }
    .location-suggestion { display: block; width: 100%; padding: 10px 14px; cursor: pointer; border: 0; border-bottom: 1px solid #F1F5F9; background: #FFFFFF; color: var(--text-main); text-align: left; font: inherit; font-size: 13px; }
    .location-suggestion:hover { background: #F8FAFC; }
    .location-suggestion small { display: block; color: var(--text-muted); margin-top: 3px; }
    .location-search-message { padding: 10px 14px; color: var(--text-muted); font-size: 13px; }
    .location-attribution { color: var(--text-muted); font-size: 11px; margin: 6px 0 0; }
    .location-attribution a { color: inherit; }

    .selected-location {
      margin-top: 10px; padding: 10px 14px; background: #F8FAFC; border-left: 3px solid var(--primary-lost);
      border-radius: 0 var(--radius-sm) var(--radius-sm) 0; font-size: 13px; color: var(--text-main); width: 100%;
    }
    .found-form-theme .selected-location { border-left-color: var(--primary-found); }

    .photo-upload-box {
      width: 100%; height: 220px; background-color: #F8FAFC; border: 2px dashed #CBD5E1;
      display: flex; flex-direction: column; justify-content: center; align-items: center; gap: 12px; margin-bottom: 24px;
      cursor: pointer; position: relative; overflow: hidden; border-radius: var(--radius-md);
    }
    .photo-upload-box:hover { border-color: var(--text-main); background-color: #F1F5F9; }
    .photo-upload-box img { width: 100%; height: 100%; object-fit: cover; position: absolute; top: 0; left: 0; }
    .file-input { display: none; }

    .submit-btn {
      width: 100%; font-family: inherit; font-size: 15px; font-weight: 700; padding: 14px;
      background-color: var(--primary-lost); border: none; border-radius: var(--radius-sm); color: #FFFFFF; cursor: pointer;
      box-shadow: 0 4px 12px rgba(217, 37, 37, 0.25);
    }
    .submit-btn:hover { background-color: var(--primary-lost-hover); transform: translateY(-1px); }
    .submit-btn.found-btn { background-color: var(--primary-found); box-shadow: 0 4px 12px rgba(0, 169, 79, 0.25); }
    .submit-btn.found-btn:hover { background-color: var(--primary-found-hover); }

    .code-display-box { background-color: #F0FDF4; border: 2px dashed var(--primary-found); border-radius: var(--radius-md); padding: 24px; text-align: center; margin: 18px 0; }
    .code-value { font-family: monospace; font-size: 28px; font-weight: 800; letter-spacing: 2px; color: var(--primary-found-hover); margin: 10px 0; }
    .btn-copy-code { background-color: var(--primary-found); color: white; border: none; padding: 10px 20px; font-weight: 700; font-size: 13px; border-radius: var(--radius-sm); cursor: pointer; }
    .btn-copy-code:hover { background-color: var(--primary-found-hover); }

    .manage-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 24px; margin-bottom: 24px; box-shadow: var(--shadow-sm); }
    .claim-item-card { background: #F8FAFC; border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 18px; margin-top: 14px; }
    .claim-actions { display: flex; gap: 12px; margin-top: 14px; }
    .btn-approve { background-color: var(--primary-found); color: white; border: none; padding: 8px 18px; border-radius: var(--radius-sm); font-weight: 700; cursor: pointer; }
    .btn-approve:hover { background-color: var(--primary-found-hover); }
    .btn-reject { background-color: var(--primary-lost); color: white; border: none; padding: 8px 18px; border-radius: var(--radius-sm); font-weight: 700; cursor: pointer; }
    .btn-reject:hover { background-color: var(--primary-lost-hover); }

    .modal-close-btn { position: absolute; top: 22px; right: 26px; background: transparent; border: none; font-size: 28px; color: var(--text-muted); cursor: pointer; }
    .modal-close-btn:hover { color: var(--text-main); }
    .claim-item-summary { display: flex; gap: 28px; align-items: flex-start; margin-bottom: 28px; padding-bottom: 24px; border-bottom: 1px solid var(--border-color); }
    .claim-item-img { width: 200px; height: 130px; object-fit: cover; border-radius: var(--radius-md); background-color: #F1F5F9; flex-shrink: 0; }
    .claim-form { display: flex; flex-direction: column; gap: 20px; }
    .claim-submit-btn { background-color: var(--primary-found); border: none; color: #FFFFFF; font-size: 16px; font-weight: 700; padding: 14px 36px; border-radius: var(--radius-sm); cursor: pointer; box-shadow: 0 4px 12px rgba(0, 169, 79, 0.25); }
    .claim-submit-btn:hover { background-color: var(--primary-found-hover); }

    footer {
      border-top: 1px solid var(--border-color); padding: 36px 48px; display: flex; justify-content: space-between; align-items: center;
      font-size: 13px; background-color: rgba(255, 255, 255, 0.9); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); margin-top: auto; position: relative; z-index: 1;
    }

    @media (max-width: 900px) {
      header { padding: 16px 24px; }
      .home-main { grid-template-columns: 1fr; gap: 40px; padding: 40px 24px; }
      .form-main { grid-template-columns: 1fr; gap: 24px; padding: 28px; }
      .filter-section { grid-template-columns: 1fr; }
      .gallery-container, .form-container { padding: 32px 24px; }
      footer { padding: 28px 24px; flex-direction: column; gap: 20px; text-align: center; }
    }
    /* ================= PREMIUM COMMUNITY EXPERIENCE ================= */
    :root {
      --primary-lost: #B4474D;
      --primary-lost-hover: #943940;
      --primary-lost-light: #FBEFED;
      --primary-found: #187357;
      --primary-found-hover: #105C45;
      --primary-found-light: #EAF5EF;
      --bg-main: #F5F7F5;
      --bg-card: #FFFFFF;
      --text-main: #17221E;
      --text-muted: #69766F;
      --text-light: #98A49D;
      --border-color: #E0E7E2;
      --border-focus: #187357;
      --radius-sm: 10px;
      --radius-md: 16px;
      --radius-lg: 24px;
      --shadow-sm: 0 2px 8px rgba(20, 39, 30, .045);
      --shadow-md: 0 14px 32px rgba(20, 39, 30, .09);
      --shadow-lg: 0 24px 60px rgba(20, 39, 30, .18);
    }
    html { scroll-behavior: smooth; }
    body { background: var(--bg-main); animation: none; color: var(--text-main); font-family: 'Plus Jakarta Sans', sans-serif; }
    .bg-decorations { display: none; }
    header {
      padding: 14px clamp(20px, 5vw, 72px);
      background: rgba(255, 255, 255, .94);
      border-bottom-color: rgba(224, 231, 226, .88);
      box-shadow: 0 5px 24px rgba(20, 39, 30, .035);
    }
    .logo { gap: 6px; font-size: 18px; letter-spacing: -.045em; white-space: nowrap; }
    .logo-icon { width: 22px; height: 22px; }
    nav ul { gap: 3px; }
    nav a { padding: 9px 12px; border-radius: 10px; font-size: 12px; font-weight: 700; }
    nav a.active, nav a#foundNav.active, nav a#reportFoundNav.active, nav a#manageNav.active { box-shadow: none; }

    .hero-container { min-height: min(740px, calc(100svh - 70px)); background: #173E3D; }
    .hero-video-wrapper video { object-position: center 48%; }
    .hero-overlay {
      background: linear-gradient(90deg, rgba(11, 35, 34, .82) 0%, rgba(11, 35, 34, .65) 48%, rgba(11, 35, 34, .30) 100%),
        linear-gradient(0deg, rgba(11, 35, 34, .38), rgba(11, 35, 34, .05) 72%);
    }
    .home-main {
      grid-template-columns: minmax(0, 1.1fr) minmax(300px, .7fr);
      max-width: 1320px; min-height: 660px; gap: clamp(36px, 7vw, 100px);
      padding: 78px clamp(24px, 6vw, 88px) 95px;
    }
    .hero-left { gap: 24px; }
    .hero-kicker {
      display: inline-flex; align-items: center; gap: 10px; color: rgba(255, 255, 255, .83) !important;
      font-size: 11px !important; font-weight: 700 !important; letter-spacing: .13em; line-height: 1.4;
      text-transform: uppercase; margin-bottom: 18px;
    }
    .hero-kicker-dot { width: 7px; height: 7px; border-radius: 50%; background: #9ED9B9; box-shadow: 0 0 0 5px rgba(158, 217, 185, .16); }
    .hero-text h1 {
      max-width: 740px; color: #FFFFFF; font-family: 'Plus Jakarta Sans', sans-serif;
      font-size: clamp(44px, 5.8vw, 72px); font-weight: 700; letter-spacing: -.065em;
      line-height: 1.04; margin-bottom: 20px;
    }
    .hero-text p:not(.hero-kicker) { max-width: 560px; color: rgba(255, 255, 255, .82); font-size: clamp(15px, 1.4vw, 17px); font-weight: 400; line-height: 1.8; }
    .image-collage { height: 130px; margin-top: 4px; opacity: .96; }
    .collage-img { border: 3px solid rgba(255, 255, 255, .92); border-radius: 16px; animation: none; }
    .img-1 { width: 112px; height: 112px; bottom: 0; left: 0; }
    .img-2 { width: 122px; height: 122px; bottom: 2px; left: 86px; }
    .img-3 { width: 130px; height: 130px; top: 0; left: 185px; }
    .hero-right { gap: 14px; }
    .action-card {
      min-height: 128px; padding: 26px 28px; border: 1px solid rgba(255, 255, 255, .27);
      border-radius: 20px; box-shadow: 0 18px 45px rgba(4, 22, 18, .18); backdrop-filter: blur(16px);
    }
    .action-card.lost { background: linear-gradient(135deg, rgba(180, 71, 77, .96), rgba(145, 50, 57, .94)); }
    .action-card.found { background: linear-gradient(135deg, rgba(24, 115, 87, .97), rgba(15, 85, 66, .96)); }
    .action-card-content span { color: rgba(255, 255, 255, .78); font-size: 10px; letter-spacing: .12em; }
    .action-card h2 { font-family: 'Plus Jakarta Sans', sans-serif; font-size: clamp(23px, 2.6vw, 30px); letter-spacing: -.045em; }
    .card-icon { width: 48px; height: 48px; background: rgba(255, 255, 255, .15); }
    .card-icon svg { width: 22px; height: 22px; }
    .hero-wave-container { margin-top: -22px; }
    .hero-wave-svg { height: 44px; }
    .wave-path { fill: var(--bg-main); animation: none; }

    .home-community-section, .home-how-section { max-width: 1240px; margin: 0 auto; padding: 74px 48px 28px; }
    .home-section-heading { display: flex; justify-content: space-between; align-items: end; gap: 24px; margin-bottom: 26px; }
    .section-eyebrow { color: var(--primary-found); font-size: 10px; font-weight: 800; letter-spacing: .15em; text-transform: uppercase; margin-bottom: 10px; }
    .home-section-heading h2 { color: var(--text-main); font-size: clamp(28px, 3vw, 38px); letter-spacing: -.055em; line-height: 1.15; margin-bottom: 9px; }
    .home-section-heading p:not(.section-eyebrow) { color: var(--text-muted); font-size: 14px; }
    .home-board-links { display: flex; align-items: center; gap: 22px; }
    .home-section-link { color: var(--primary-found); font-size: 12px; font-weight: 800; text-decoration: none; cursor: pointer; white-space: nowrap; transition: color .2s ease; }
    .home-section-link span { display: inline-block; margin-left: 4px; transition: transform .2s ease; }
    .home-section-link:hover { color: var(--primary-found-hover); }
    .home-section-link:hover span { transform: translateX(4px); }
    .home-recent-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
    .home-report-card {
      min-width: 0; min-height: 190px; display: flex; flex-direction: column; padding: 22px;
      background: rgba(255, 255, 255, .88); border: 1px solid var(--border-color); border-radius: 18px;
      box-shadow: var(--shadow-sm); transition: transform .25s ease, box-shadow .25s ease, border-color .25s ease;
      animation: cardFadeIn .45s ease both;
    }
    .home-report-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-md); border-color: #CDD9D1; }
    .home-report-topline, .home-report-footer { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .home-report-type { display: inline-flex; align-items: center; gap: 7px; color: var(--primary-lost); font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .home-report-type::before { content: ''; width: 7px; height: 7px; background: currentColor; border-radius: 50%; }
    .home-report-card.is-found .home-report-type { color: var(--primary-found); }
    .home-report-category { max-width: 46%; overflow: hidden; color: var(--text-muted); font-size: 10px; font-weight: 700; text-overflow: ellipsis; white-space: nowrap; }
    .home-report-card h3 { margin: 21px 0 9px; color: var(--text-main); font-size: 17px; font-weight: 700; letter-spacing: -.025em; line-height: 1.4; }
    .home-report-location { color: var(--text-muted); font-size: 12px; }
    .home-report-location span { color: var(--primary-found); font-size: 15px; }
    .home-report-footer { margin-top: auto; padding-top: 18px; color: var(--text-light); font-size: 10px; }
    .home-report-footer button { border: 0; background: transparent; color: var(--text-main); font: inherit; font-size: 11px; font-weight: 800; cursor: pointer; }
    .home-report-footer button span { color: var(--primary-found); margin-left: 4px; }
    .home-report-footer button:hover { color: var(--primary-found); }
    .home-empty-state { display: flex; align-items: center; gap: 18px; padding: 24px; background: #fff; border: 1px solid var(--border-color); border-radius: 18px; }
    .home-empty-icon { width: 44px; height: 44px; display: grid; place-items: center; flex: 0 0 auto; color: var(--primary-found); background: var(--primary-found-light); border-radius: 14px; font-size: 20px; }
    .home-empty-state h3 { font-size: 15px; margin-bottom: 4px; }
    .home-empty-state p { max-width: 600px; color: var(--text-muted); font-size: 12px; }
    .home-empty-state .home-section-link { margin-left: auto; }
    .home-how-section { padding-top: 58px; padding-bottom: 84px; }
    .home-how-heading { margin-bottom: 22px; }
    .home-steps-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
    .home-step-card { min-height: 175px; padding: 23px; background: #EEF3EF; border-radius: 18px; }
    .home-step-number { color: var(--primary-found); font-size: 10px; font-weight: 800; letter-spacing: .12em; }
    .home-step-card h3 { margin: 23px 0 8px; font-size: 15px; letter-spacing: -.02em; }
    .home-step-card p { color: var(--text-muted); font-size: 12px; line-height: 1.7; }

    .gallery-container { max-width: 1240px; padding: 54px 48px 72px; }
    .banner-container { margin-bottom: 24px; padding-bottom: 22px; }
    .page-title-banner { flex-wrap: wrap; }
    .page-title-banner h2, .form-header-title { font-family: 'Plus Jakarta Sans', sans-serif; font-size: clamp(28px, 3.2vw, 38px); letter-spacing: -.055em; }
    .banner-badge { border-radius: 999px; font-size: 9px; padding: 7px 12px; }
    .filter-section { gap: 14px; padding: 20px; border-radius: 18px; box-shadow: var(--shadow-sm); }
    .filter-group label, .input-group label { font-size: 10px; letter-spacing: .08em; }
    .filter-group input, .filter-group select, .input-group input, .input-group select, .input-group textarea {
      min-height: 46px; border-color: #DCE5DF; border-radius: 11px; box-shadow: 0 1px 2px rgba(20, 39, 30, .025);
      transition: border-color .2s ease, box-shadow .2s ease, background .2s ease;
    }
    .filter-group input:focus, .filter-group select:focus, .input-group input:focus, .input-group select:focus, .input-group textarea:focus {
      border-color: #6AAB90; box-shadow: 0 0 0 4px rgba(24, 115, 87, .10);
    }
    .items-grid { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 18px; }
    .item-card { border-radius: 18px; box-shadow: var(--shadow-sm); }
    .item-card:hover { box-shadow: var(--shadow-md); border-color: #CFDCD3; }
    .item-img-placeholder { height: 205px; background: linear-gradient(135deg, #E6EFEB, #F5F7F5); border-bottom: 0; }
    .item-img-placeholder span { color: #87968D; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .item-body { padding: 19px; }
    .item-category-badge { padding: 5px 9px; border-radius: 7px; font-size: 9px; letter-spacing: .07em; }
    .item-title { font-size: 16px; letter-spacing: -.025em; }
    .item-meta, .item-location { font-size: 11px; }
    .item-actions { gap: 9px; }
    .btn-found-this, .btn-contact-claimer, .item-details-btn, .pagination-btn { min-height: 42px; border-radius: 10px; }
    .btn-found-this, .btn-contact-claimer { box-shadow: none; font-size: 11px; }
    .item-details-btn { font-size: 11px; }

    .form-container { max-width: 1050px; padding: 60px 48px 76px; }
    .form-header-sub { max-width: 640px; font-size: 13px; margin-bottom: 26px; }
    .form-main { gap: 32px; padding: 32px; border-radius: 20px; box-shadow: var(--shadow-sm); }
    .form-column h3 { font-size: 13px; letter-spacing: -.01em; }
    .input-group { margin-bottom: 15px; }
    .photo-upload-box { min-height: 250px; border-color: #CBD9D0; border-radius: 15px; background: #F7FAF8; }
    .photo-upload-box:hover { border-color: var(--primary-found); background: #F0F7F2; }
    .submit-btn, .claim-submit-btn { min-height: 48px; border-radius: 11px; box-shadow: none; font-size: 13px; }
    .submit-btn:not(.found-btn) { background-color: var(--primary-lost); }
    .submit-btn.found-btn, .claim-submit-btn { background-color: var(--primary-found); }
    .submit-btn:hover, .claim-submit-btn:hover { filter: brightness(.94); }
    .selected-location { border-radius: 10px; border-left-width: 3px; background: #F4F7F5; }
    .manage-card, .claim-item-card { border-radius: 16px; padding: 22px; }
    .claim-item-card { background: #F8FAF8; }
    .claim-actions { flex-wrap: wrap; }
    .btn-approve, .btn-reject { min-height: 40px; border-radius: 9px; }
    .modal-overlay { background: rgba(10, 24, 20, .62); }
    .modal-card { border: 1px solid rgba(255, 255, 255, .8); border-radius: 22px; padding: 32px; }
    .claim-modal-card { max-height: min(90vh, 900px); padding: 34px; }
    .modal-close-btn { top: 14px; right: 18px; width: 40px; height: 40px; border-radius: 50%; font-size: 25px; }
    .modal-close-btn:hover { background: #F2F6F3; }
    .claim-form { gap: 16px; }
    .claim-item-summary { gap: 20px; }
    .claim-item-img { border-radius: 13px; }
    .code-display-box { background: #F1F8F3; border: 1px dashed #7FB49A; border-radius: 16px; }
    .code-value { color: var(--primary-found); }
    .btn-copy-code { border-radius: 9px; }
    footer { padding: 30px clamp(20px, 5vw, 72px); background: #FFFFFF; border-top-color: var(--border-color); }
    footer a { text-decoration: none; font-size: 11px; font-weight: 700; transition: color .2s ease; }
    footer a:hover { color: var(--primary-found) !important; }
    .footer-center { letter-spacing: -.04em; }

    .recovery-request-card { max-width: 820px; max-height: min(92vh, 920px); overflow-y: auto; text-align: left; }
    .recovery-form-title { margin: -3px 0 8px; color: var(--text-main); font-size: 27px; letter-spacing: -.05em; }
    .recovery-form-subtitle { max-width: 650px; margin-bottom: 22px; color: var(--text-muted); font-size: 12px; line-height: 1.7; }
    .recovery-fields-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
    .recovery-photo-field input { padding: 9px 11px; font-size: 11px; background: #F7FAF8; }
    .recovery-consent { display: flex; align-items: flex-start; gap: 11px; margin-top: -3px; color: var(--text-main); font-size: 11px; font-weight: 600; line-height: 1.6; cursor: pointer; }
    .recovery-consent input { width: 18px; height: 18px; flex: 0 0 18px; margin-top: 1px; accent-color: var(--primary-found); }
    .recovery-privacy-note { margin-top: -7px; color: var(--text-muted); font-size: 10px; line-height: 1.6; }
    .recovery-request-card .claim-submit-btn { width: 100%; margin-top: 3px; }
    .recovery-dashboard-section { margin: 24px 0 28px; padding: 22px; border: 1px solid var(--border-color); border-radius: 17px; background: #FCFDFC; }
    .recovery-dashboard-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 15px; }
    .recovery-dashboard-heading .section-eyebrow { margin-bottom: 5px; }
    .recovery-dashboard-heading h4 { color: var(--text-main); font-size: 18px; letter-spacing: -.035em; }
    .recovery-unread-badge, .recovery-new-indicator { display: inline-flex; align-items: center; color: #8B4C16; background: #FFF3DE; border-radius: 999px; font-size: 9px; font-weight: 800; letter-spacing: .03em; }
    .recovery-unread-badge { padding: 7px 11px; }
    .recovery-request-list { display: flex; flex-direction: column; gap: 9px; }
    .recovery-request-row { display: flex; justify-content: space-between; align-items: center; gap: 18px; padding: 15px; border: 1px solid #E5ECE7; border-radius: 13px; background: #FFFFFF; transition: border-color .2s ease, box-shadow .2s ease; }
    .recovery-request-row.is-unread { border-color: #BFD9C9; background: #F8FCF9; }
    .recovery-request-row-main { min-width: 0; }
    .recovery-request-row-meta { display: flex; align-items: center; gap: 7px; margin-bottom: 7px; }
    .recovery-status-pill { display: inline-flex; padding: 5px 8px; color: var(--primary-found); background: var(--primary-found-light); border-radius: 999px; font-size: 9px; font-weight: 800; }
    .recovery-new-indicator { padding: 5px 8px; }
    .recovery-request-row h5 { margin-bottom: 4px; color: var(--text-main); font-size: 13px; }
    .recovery-request-row p { color: var(--text-muted); font-size: 10px; line-height: 1.6; }
    .recovery-submitted-date { display: block; margin-top: 5px; color: var(--text-light); font-size: 9px; }
    .recovery-view-button { flex: 0 0 auto; min-height: 40px; padding: 0 13px; color: var(--primary-found); background: #FFFFFF; border: 1px solid #D7E4DB; border-radius: 10px; font: inherit; font-size: 10px; font-weight: 800; cursor: pointer; }
    .recovery-view-button:hover { background: var(--primary-found-light); }
    .recovery-view-button span { margin-left: 3px; }
    .recovery-empty-state { display: flex; align-items: center; gap: 11px; padding: 17px; border-radius: 12px; background: #F3F7F4; }
    .recovery-empty-state > span { color: var(--primary-found); font-size: 17px; }
    .recovery-empty-state p { color: var(--text-muted); font-size: 11px; }
    .recovery-details-card { max-width: 760px; max-height: min(92vh, 900px); overflow-y: auto; text-align: left; }
    .recovery-detail-title { margin: -2px 0 4px; padding-right: 36px; font-size: 25px; letter-spacing: -.05em; }
    .recovery-detail-subtitle { color: var(--text-muted); font-size: 11px; }
    .recovery-detail-summary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 20px 0; padding: 17px; border: 1px solid var(--border-color); border-radius: 14px; background: #F8FAF8; }
    .recovery-detail-summary div { min-width: 0; }
    .recovery-detail-summary span, .recovery-status-editor > div > span { display: block; margin-bottom: 4px; color: var(--text-muted); font-size: 9px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
    .recovery-detail-summary strong { display: block; color: var(--text-main); font-size: 11px; line-height: 1.5; overflow-wrap: anywhere; }
    .recovery-detail-block { margin-bottom: 17px; }
    .recovery-detail-block h4, .recovery-evidence h4 { margin-bottom: 7px; color: var(--text-main); font-size: 11px; }
    .recovery-detail-block p { color: var(--text-muted); font-size: 12px; line-height: 1.75; overflow-wrap: anywhere; }
    .recovery-contact-panel { display: flex; justify-content: space-between; align-items: center; gap: 18px; margin: 18px 0; padding: 17px; border: 1px solid #CFE2D5; border-radius: 14px; background: #F0F8F2; }
    .recovery-contact-panel .section-eyebrow { margin-bottom: 5px; font-size: 8px; }
    .recovery-contact-panel h3 { margin-bottom: 4px; font-size: 14px; }
    .recovery-contact-panel p:not(.section-eyebrow) { color: var(--text-muted); font-size: 10px; line-height: 1.6; overflow-wrap: anywhere; }
    .recovery-contact-actions { display: flex; flex-wrap: wrap; gap: 7px; }
    .recovery-contact-actions a { display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 0 12px; color: #FFFFFF; background: var(--primary-found); border-radius: 9px; text-decoration: none; font-size: 10px; font-weight: 800; white-space: nowrap; }
    .recovery-contact-actions a:hover { background: var(--primary-found-hover); }
    .recovery-evidence { margin: 16px 0; }
    .recovery-evidence img { display: block; width: 100%; max-height: 300px; object-fit: contain; border: 1px solid var(--border-color); border-radius: 12px; background: #F4F7F5; }
    .recovery-status-editor { display: grid; grid-template-columns: minmax(0, 1fr) minmax(190px, .8fr) auto; align-items: center; gap: 10px; margin-top: 18px; padding-top: 17px; border-top: 1px solid var(--border-color); }
    .recovery-status-editor strong { font-size: 11px; }
    .recovery-status-editor select { min-width: 0; min-height: 42px; padding: 9px 11px; border: 1px solid var(--border-color); border-radius: 10px; background: #FFFFFF; color: var(--text-main); font: inherit; font-size: 10px; }
    .recovery-status-editor .submit-btn { width: auto; min-height: 42px; padding: 0 14px; font-size: 10px; }

    @media (max-width: 900px) {
      header { gap: 12px; }
      .home-main { grid-template-columns: minmax(0, 1fr) minmax(270px, .8fr); gap: 28px; min-height: 590px; padding: 64px 30px 82px; }
      .hero-text h1 { font-size: clamp(42px, 6vw, 60px); }
      .image-collage { transform: scale(.82); transform-origin: left top; margin-bottom: -20px; }
      .action-card { padding: 22px; }
      .home-community-section, .home-how-section { padding-left: 30px; padding-right: 30px; }
      .gallery-container, .form-container { padding-left: 30px; padding-right: 30px; }
    }
    @media (max-width: 700px) {
      header { position: relative; flex-direction: column; align-items: flex-start; padding: 13px 18px 10px; }
      .logo { font-size: 17px; }
      header nav { width: 100%; overflow: visible; }
      nav ul { display: grid; width: 100%; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 4px; }
      nav a { display: block; padding: 9px 5px; text-align: center; font-size: 10px; white-space: nowrap; }
      .hero-container { min-height: auto; }
      .hero-video-wrapper video { object-position: 57% center; }
      .hero-overlay { background: linear-gradient(90deg, rgba(11, 35, 34, .79), rgba(11, 35, 34, .49)), linear-gradient(0deg, rgba(11, 35, 34, .42), rgba(11, 35, 34, .12)); }
      .home-main { grid-template-columns: 1fr; gap: 29px; min-height: 0; padding: 60px 22px 66px; }
      .hero-kicker { margin-bottom: 14px; font-size: 9px !important; letter-spacing: .1em; }
      .hero-text h1 { font-size: clamp(42px, 12vw, 58px); }
      .hero-text p:not(.hero-kicker) { font-size: 14px; line-height: 1.7; }
      .image-collage { display: none; }
      .hero-right { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
      .action-card { min-height: 116px; align-items: flex-start; flex-direction: column-reverse; gap: 12px; padding: 15px; border-radius: 15px; }
      .action-card-content span { font-size: 8px; letter-spacing: .08em; }
      .action-card h2 { font-size: 18px; }
      .card-icon { width: 34px; height: 34px; }
      .card-icon svg { width: 17px; height: 17px; }
      .hero-wave-container { margin-top: -13px; }
      .hero-wave-svg { height: 26px; }
      .home-community-section, .home-how-section { padding: 48px 20px 12px; }
      .home-section-heading { align-items: flex-start; flex-direction: column; gap: 14px; margin-bottom: 20px; }
      .home-board-links { gap: 18px; }
      .home-section-heading h2 { font-size: 29px; }
      .home-section-heading p:not(.section-eyebrow) { font-size: 12px; }
      .home-recent-grid, .home-steps-grid { grid-template-columns: 1fr; gap: 10px; }
      .home-report-card { min-height: 166px; padding: 18px; }
      .home-report-card h3 { margin-top: 17px; }
      .home-empty-state { align-items: flex-start; flex-wrap: wrap; padding: 18px; }
      .home-empty-state div { flex: 1 1 calc(100% - 64px); }
      .home-empty-state .home-section-link { margin-left: 62px; }
      .home-how-section { padding-top: 48px; padding-bottom: 56px; }
      .home-step-card { min-height: 0; padding: 20px; }
      .home-step-card h3 { margin-top: 14px; }
      .gallery-container, .form-container { padding: 38px 18px 52px; }
      .banner-container { align-items: flex-start; }
      .page-title-banner { align-items: flex-start; flex-direction: column; gap: 9px; }
      .page-title-banner h2, .form-header-title { font-size: 29px; }
      .filter-section { grid-template-columns: 1fr; gap: 12px; padding: 15px; }
      .items-grid { grid-template-columns: 1fr; gap: 14px; }
      .item-img-placeholder { height: 220px; }
      .form-main { grid-template-columns: 1fr; gap: 20px; padding: 20px; }
      .form-column h3 { margin-bottom: 15px; }
      .photo-upload-box { min-height: 200px; }
      .claim-modal-card { padding: 27px 18px 20px; }
      .recovery-request-card { padding: 27px 18px 20px; }
      .recovery-fields-grid { grid-template-columns: 1fr; gap: 0; }
      .recovery-dashboard-section { padding: 17px 13px; }
      .recovery-request-row { align-items: flex-start; flex-direction: column; gap: 10px; padding: 13px; }
      .recovery-view-button { width: 100%; }
      .recovery-details-card { padding: 28px 18px 20px; }
      .recovery-detail-summary { grid-template-columns: 1fr; gap: 10px; }
      .recovery-contact-panel { align-items: flex-start; flex-direction: column; }
      .recovery-status-editor { grid-template-columns: 1fr; }
      .recovery-status-editor select, .recovery-status-editor .submit-btn { width: 100%; }
      .claim-item-summary { flex-direction: column; gap: 14px; }
      .claim-item-img { width: 100%; height: 180px; }
      .claim-form > div[style*="grid-template-columns"] { grid-template-columns: 1fr !important; gap: 0 !important; }
      .modal-card { padding: 28px 20px 22px; }
      #managePage .form-main > .input-group > div[style*="display: flex"] { flex-direction: column; }
      #managementCodeInput + button { width: 100% !important; min-height: 46px; }
      footer { padding: 24px 18px; flex-direction: column; gap: 16px; text-align: center; }
      footer .footer-col:first-child { display: grid !important; grid-template-columns: repeat(2, auto); justify-content: center; gap: 10px 18px !important; }
    }
    @media (max-width: 380px) {
      .hero-right { grid-template-columns: 1fr; }
      .action-card { min-height: 86px; flex-direction: row; align-items: center; }
      .action-card h2 { font-size: 21px; }
      nav a { font-size: 9px; }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
    }
  </style>
</head>

<body>

  <!-- BACKGROUND DECORATIONS -->
  <div class="bg-decorations">
    <svg class="bg-shape palm-leaf-1" viewBox="0 0 100 100" fill="none" stroke="#00A94F" stroke-width="2" stroke-linecap="round">
      <path d="M10,90 Q50,50 90,10 M50,50 Q30,30 20,40 M50,50 Q70,30 80,40 M50,50 Q30,70 40,80 M50,50 Q70,70 60,80"/>
    </svg>
    <svg class="bg-shape palm-leaf-2" viewBox="0 0 100 100" fill="none" stroke="#00A9DC" stroke-width="2" stroke-linecap="round">
      <path d="M10,10 Q50,50 90,90 M50,50 Q30,30 40,20 M50,50 Q70,30 60,20 M50,50 Q30,70 20,60 M50,50 Q70,70 80,60"/>
    </svg>
    <div class="bg-shape bg-bubble-1"></div>
    <div class="bg-shape bg-bubble-2"></div>
  </div>

  <!-- HEADER -->
  <header>
    <a class="logo" onclick="showPage('homePage', 'homeNav')">
      Siargao<span class="red-text">Lost</span>&<span class="green-text">Found</span>
      <span class="logo-icon"></span>
    </a>

    <nav>
      <ul>
        <li><a id="homeNav" class="active" onclick="showPage('homePage', 'homeNav')">Home</a></li>
        <li><a id="lostNav" onclick="showPage('lostPage', 'lostNav')">Lost Items</a></li>
        <li><a id="reportLostNav" onclick="showPage('reportLostPage', 'reportLostNav')">Report Lost</a></li>
        <li><a id="foundNav" onclick="showPage('foundPage', 'foundNav')">Found Items</a></li>
        <li><a id="reportFoundNav" onclick="showPage('reportFoundPage', 'reportFoundNav')">Report Found</a></li>
        <li><a id="manageNav" onclick="showPage('managePage', 'manageNav')">Manage Report</a></li>
      </ul>
    </nav>
  </header>

  <!-- HOME PAGE -->
  <main id="homePage" class="page active-page">
    <div class="hero-container">
      <div class="hero-video-wrapper">
        <video autoplay muted loop playsinline preload="metadata">
          <source src="beach.mp4" type="video/mp4">
        </video>
      </div>
      <div class="hero-overlay"></div>

      <div class="home-main">
        <section class="hero-left">
          <div class="hero-text">
            <p class="hero-kicker"><span class="hero-kicker-dot"></span> A community recovery platform for Siargao</p>
            <h1>Lost on the island?<br>Let’s bring it home.</h1>
            <p>One trusted place for locals, students, and travelers to report missing belongings, share found items, and reconnect them with their owners.</p>
          </div>

          <div class="image-collage">
            <img class="collage-img img-1" src="https://images.unsplash.com/photo-1582139329536-e7284fece509?auto=format&fit=crop&w=400&q=80" alt="Keys">
            <img class="collage-img img-2" src="https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?auto=format&fit=crop&w=400&q=80" alt="Phone">
            <img class="collage-img img-3" src="https://images.unsplash.com/photo-1517336714731-489689fd1ca8?auto=format&fit=crop&w=400&q=80" alt="Laptop">
          </div>
        </section>

        <section class="hero-right">
          <a class="action-card lost" onclick="showPage('reportLostPage', 'reportLostNav')">
            <div class="action-card-content">
              <span>Missing an item?</span>
              <h2>Report Lost</h2>
            </div>
            <div class="card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
            </div>
          </a>

          <a class="action-card found" onclick="showPage('reportFoundPage', 'reportFoundNav')">
            <div class="action-card-content">
              <span>Found something?</span>
              <h2>Report Found</h2>
            </div>
            <div class="card-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
              </svg>
            </div>
          </a>
        </section>
      </div>

      <div class="hero-wave-container">
        <svg class="hero-wave-svg" viewBox="0 0 1200 120" preserveAspectRatio="none">
          <path class="wave-path" d="M0,0 C150,90 350,-40 500,40 C650,120 900,10 1200,40 L1200,120 L0,120 Z"></path>
        </svg>
      </div>
    </div>

    <?php
      $homeRecentItems = [];
      foreach ($lostItemsPHP as $recentItem) {
          $recentItem['home_type'] = 'lost';
          $homeRecentItems[] = $recentItem;
      }
      foreach ($foundItemsPHP as $recentItem) {
          $recentItem['home_type'] = 'found';
          $homeRecentItems[] = $recentItem;
      }
      usort($homeRecentItems, function ($a, $b) {
          return ($b['id'] ?? 0) <=> ($a['id'] ?? 0);
      });
      $homeRecentItems = array_slice($homeRecentItems, 0, 3);
    ?>
    <section class="home-community-section" aria-labelledby="recentReportsTitle">
      <div class="home-section-heading">
        <div>
          <p class="section-eyebrow">The community board</p>
          <h2 id="recentReportsTitle">Recently reported</h2>
          <p>The latest reports from around Siargao, shared by the community.</p>
        </div>
        <div class="home-board-links">
          <a class="home-section-link" onclick="showPage('lostPage', 'lostNav')">Lost reports <span aria-hidden="true">→</span></a>
          <a class="home-section-link" onclick="showPage('foundPage', 'foundNav')">Found reports <span aria-hidden="true">→</span></a>
        </div>
      </div>
      <?php if (!empty($homeRecentItems)): ?>
        <div class="home-recent-grid">
          <?php foreach ($homeRecentItems as $recentItem): ?>
            <article class="home-report-card <?php echo $recentItem['home_type'] === 'found' ? 'is-found' : 'is-lost'; ?>">
              <div class="home-report-topline">
                <span class="home-report-type"><?php echo $recentItem['home_type'] === 'found' ? 'Found item' : 'Lost item'; ?></span>
                <span class="home-report-category"><?php echo htmlspecialchars(ucfirst($recentItem['category'] ?? 'Item'), ENT_QUOTES, 'UTF-8'); ?></span>
              </div>
              <h3><?php echo htmlspecialchars($recentItem['title'] ?? 'Untitled item', ENT_QUOTES, 'UTF-8'); ?></h3>
              <p class="home-report-location"><span aria-hidden="true">⌖</span> <?php echo htmlspecialchars($recentItem['location']['name'] ?? 'Siargao', ENT_QUOTES, 'UTF-8'); ?></p>
              <div class="home-report-footer">
                <span>Reported <?php echo htmlspecialchars($recentItem['date'] ?? '', ENT_QUOTES, 'UTF-8'); ?></span>
                <button type="button" onclick="showPage('<?php echo $recentItem['home_type'] === 'found' ? 'foundPage' : 'lostPage'; ?>', '<?php echo $recentItem['home_type'] === 'found' ? 'foundNav' : 'lostNav'; ?>')">View <?php echo $recentItem['home_type'] === 'found' ? 'found' : 'lost'; ?> listings <span aria-hidden="true">→</span></button>
              </div>
            </article>
          <?php endforeach; ?>
        </div>
      <?php else: ?>
        <div class="home-empty-state">
          <span class="home-empty-icon" aria-hidden="true">✦</span>
          <div><h3>Your community board starts here</h3><p>There are no reports yet. Share a lost or found item to help the island community reconnect it with its owner.</p></div>
          <a class="home-section-link" onclick="showPage('reportLostPage', 'reportLostNav')">Create a report <span aria-hidden="true">→</span></a>
        </div>
      <?php endif; ?>
    </section>

    <section class="home-how-section" aria-labelledby="howItWorksTitle">
      <div class="home-section-heading home-how-heading">
        <div>
          <p class="section-eyebrow">Simple by design</p>
          <h2 id="howItWorksTitle">A little help goes a long way.</h2>
          <p>Clear reports and careful verification help belongings find their way back.</p>
        </div>
      </div>
      <div class="home-steps-grid">
        <article class="home-step-card"><span class="home-step-number">01</span><h3>Share the details</h3><p>Post what was lost or found, where it happened, and the details that can help someone recognize it.</p></article>
        <article class="home-step-card"><span class="home-step-number">02</span><h3>Search the board</h3><p>Browse recent reports and use search and category filters to narrow down what you are looking for.</p></article>
        <article class="home-step-card"><span class="home-step-number">03</span><h3>Verify and reconnect</h3><p>Owners can submit identifying details so the person holding an item can review a claim with care.</p></article>
      </div>
    </section>
  </main>

  <!-- LOST GALLERY PAGE -->
  <main id="lostPage" class="page">
    <div class="gallery-container">
      <div class="banner-container">
        <div class="page-title-banner">
          <h2>Lost Items</h2>
          <span class="banner-badge lost-badge">Seeking Retrieval</span>
        </div>
      </div>

      <div class="filter-section">
        <div class="filter-group">
          <label>Search Lost Items</label>
          <input type="text" id="searchLostInput" placeholder="Search by title, description, or location..." oninput="filterLostItems()">
        </div>
        <div class="filter-group">
          <label>Category</label>
          <select id="filterCategoryLost" onchange="filterLostItems()">
            <option value="all">All Categories</option>
            <option value="phone">Phone</option>
            <option value="keys">Keys</option>
            <option value="wallet">Wallet</option>
            <option value="bag">Bag</option>
            <option value="clothing">Clothing</option>
            <option value="accessories">Accessories</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="filter-group">
          <label>Sort By Date</label>
          <select id="sortLostDate" onchange="filterLostItems()">
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
          </select>
        </div>
      </div>

      <div class="items-grid" id="lostItemsGrid"></div>
      <div class="pagination-container" id="lostPagination"></div>

      <div class="thank-you-note">
        Thank you for helping keep Siargao honest and safe.
      </div>
    </div>
  </main>

  <!-- REPORT LOST FORM PAGE -->
  <main id="reportLostPage" class="page">
    <div class="form-container">
      <h2 class="form-header-title">Report a Lost Item</h2>
      <p class="form-header-sub">Provide as much detail as possible to help community members identify your item.</p>

      <form id="lostForm" class="form-main" onsubmit="handleLostSubmit(event)">
        <div class="form-column">
          <h3>Item Information</h3>

          <div class="input-group">
            <label for="itemCategory">Category *</label>
            <select id="itemCategory" required>
              <option value="" disabled selected>Select Category</option>
              <option value="phone">Phone</option>
              <option value="keys">Keys</option>
              <option value="wallet">Wallet</option>
              <option value="laptop">Laptop</option>
              <option value="bag">Bag</option>
              <option value="clothing">Clothing</option>
              <option value="accessories">Accessories</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div class="input-group">
            <label for="itemTitle">Item Title *</label>
            <input type="text" id="itemTitle" placeholder="e.g. Black iPhone 13" required>
          </div>

          <div class="input-group">
            <label for="itemDetails">Details & Description *</label>
            <input type="text" id="itemDetails" placeholder="e.g. Black case, lost near Cloud 9" required>
          </div>

          <div class="input-group">
            <label for="fullName">Full Name *</label>
            <input type="text" id="fullName" placeholder="Your full name" required>
          </div>

          <div class="input-group">
            <label for="address">Local Address / Resort</label>
            <input type="text" id="address" placeholder="General Luna">
          </div>

          <div class="input-group">
            <label for="phoneNumber">Phone Number *</label>
            <input type="tel" id="phoneNumber" placeholder="09XX XXX XXXX" required>
          </div>

          <div class="input-group">
            <label for="email">Email Address</label>
            <input type="email" id="email" placeholder="name@example.com">
          </div>

          <div class="location-section">
            <div class="input-group" style="margin-bottom:4px;">
              <label for="lostLocationSearch">Last Known Location *</label>
            </div>
            <div class="location-search-wrap">
              <input type="text" id="lostLocationSearch" placeholder="Search location in Siargao..." autocomplete="off" required oninput="searchLocation('lost')">
              <div id="lostLocationSuggestions" class="location-suggestions"></div>
            </div>
            <p class="location-attribution">Place search by <a href="https://github.com/komoot/photon" target="_blank" rel="noopener noreferrer">Photon</a> · © <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap contributors</a></p>
            <div id="selectedLostLocation" class="selected-location">No location selected yet.</div>
            <button type="button" style="margin-top:8px; padding:6px 12px; border:1px solid var(--border-color); background:#fff; border-radius:6px; cursor:pointer;" onclick="resetLocation('lost')">Clear Location</button>
          </div>
        </div>

        <div class="form-column">
          <h3>Media & Submission</h3>
          <div class="input-group"><label>Item Photo (Max 5MB)</label></div>
          <div class="photo-upload-box" id="uploadBoxLost" onclick="document.getElementById('fileInputLost').click()">
            <span class="photo-upload-text">Click to upload photo</span>
            <input type="file" id="fileInputLost" class="file-input" accept="image/*" onchange="previewImage(event, 'lost')">
          </div>
          <div class="submit-container">
            <button type="submit" class="submit-btn" id="lostSubmitBtn">Publish Lost Report</button>
          </div>
        </div>
      </form>
    </div>
  </main>

  <!-- FOUND GALLERY PAGE -->
  <main id="foundPage" class="page">
    <div class="gallery-container">
      <div class="banner-container">
        <div class="page-title-banner">
          <h2>Found Items</h2>
          <span class="banner-badge found-badge">Awaiting Owner</span>
        </div>
      </div>

      <div class="filter-section">
        <div class="filter-group">
          <label>Search Found Items</label>
          <input type="text" id="searchFoundInput" placeholder="Search by title, description, or location..." oninput="filterFoundItems()">
        </div>
        <div class="filter-group">
          <label>Category</label>
          <select id="filterCategoryFound" onchange="filterFoundItems()">
            <option value="all">All Categories</option>
            <option value="phone">Phone</option>
            <option value="keys">Keys</option>
            <option value="wallet">Wallet</option>
            <option value="bag">Bag</option>
            <option value="clothing">Clothing</option>
            <option value="accessories">Accessories</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="filter-group">
          <label>Status</label>
          <select id="filterStatusFound" onchange="filterFoundItems()">
            <option value="active">Active & In Progress</option>
            <option value="returned">Returned to Owner</option>
            <option value="all">All Statuses</option>
          </select>
        </div>
      </div>

      <div class="items-grid" id="foundItemsGrid"></div>
      <div class="pagination-container" id="foundPagination"></div>

      <div class="thank-you-note">
        Reuniting items with their rightful owners everyday.
      </div>
    </div>
  </main>

  <!-- REPORT FOUND PAGE -->
  <main id="reportFoundPage" class="page">
    <div class="form-container">
      <h2 class="form-header-title">Report a Found Item</h2>
      <p class="form-header-sub">Found something? Submit details to help the owner track it down.</p>

      <form id="foundForm" class="form-main found-form-theme" onsubmit="handleFoundSubmit(event)">
        <div class="form-column">
          <h3>Item Details</h3>

          <div class="input-group">
            <label for="foundItemCategory">Category *</label>
            <select id="foundItemCategory" required>
              <option value="" disabled selected>Select Category</option>
              <option value="phone">Phone</option>
              <option value="keys">Keys</option>
              <option value="wallet">Wallet</option>
              <option value="laptop">Laptop</option>
              <option value="bag">Bag</option>
              <option value="clothing">Clothing</option>
              <option value="accessories">Accessories</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div class="input-group">
            <label for="foundItemTitle">Item Title *</label>
            <input type="text" id="foundItemTitle" placeholder="e.g. Black iPhone" required>
          </div>

          <div class="input-group">
            <label for="foundItemDetails">Description & Condition *</label>
            <input type="text" id="foundItemDetails" placeholder="e.g. Black phone with a cracked area" required>
          </div>

          <div class="input-group">
            <label for="foundFullName">Your Name *</label>
            <input type="text" id="foundFullName" placeholder="Full Name" required>
          </div>

          <div class="input-group">
            <label for="foundPhoneNumber">Contact Number *</label>
            <input type="tel" id="foundPhoneNumber" placeholder="09XX XXX XXXX" required>
          </div>

          <div class="input-group">
            <label for="foundEmail">Email Address</label>
            <input type="email" id="foundEmail" placeholder="name@example.com">
          </div>

          <div class="location-section">
            <div class="input-group" style="margin-bottom:4px;">
              <label for="foundLocationSearch">Found Location *</label>
            </div>
            <div class="location-search-wrap">
              <input type="text" id="foundLocationSearch" placeholder="Search location in Siargao..." autocomplete="off" required oninput="searchLocation('found')">
              <div id="foundLocationSuggestions" class="location-suggestions"></div>
            </div>
            <p class="location-attribution">Place search by <a href="https://github.com/komoot/photon" target="_blank" rel="noopener noreferrer">Photon</a> · © <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap contributors</a></p>
            <div id="selectedFoundLocation" class="selected-location">No location selected yet.</div>
            <button type="button" style="margin-top:8px; padding:6px 12px; border:1px solid var(--border-color); background:#fff; border-radius:6px; cursor:pointer;" onclick="resetLocation('found')">Clear Location</button>
          </div>
        </div>

        <div class="form-column">
          <h3>Photo & Submit</h3>
          <div class="input-group"><label>Item Photo (Max 5MB)</label></div>
          <div class="photo-upload-box" id="uploadBoxFound" onclick="document.getElementById('fileInputFound').click()">
            <span class="photo-upload-text">Click to upload photo</span>
            <input type="file" id="fileInputFound" class="file-input" accept="image/*" onchange="previewImage(event, 'found')">
          </div>
          <div class="submit-container">
            <button type="submit" class="submit-btn found-btn" id="foundSubmitBtn">Publish Found Report</button>
          </div>
        </div>
      </form>
    </div>
  </main>

  <!-- MANAGE REPORT PAGE -->
  <main id="managePage" class="page">
    <div class="form-container">
      <h2 class="form-header-title">Manage My Report</h2>
      <p class="form-header-sub">Enter your private Management Code to manage your report, review claims, or mark an item as returned.</p>

      <div class="form-main" style="grid-template-columns: 1fr;">
        <div class="input-group">
          <label for="managementCodeInput">Enter your private Management Code:</label>
          <div style="display: flex; gap: 10px;">
            <input type="text" id="managementCodeInput" placeholder="SF-XXXXXX" style="text-transform: uppercase;">
            <button type="button" class="submit-btn found-btn" style="width: auto; padding: 0 24px;" onclick="handleManageReport()">Manage Report</button>
          </div>
          <p id="manageErrorMsg" style="color: var(--primary-lost); font-size: 13px; font-weight: 600; margin-top: 8px; display: none;"></p>
        </div>

        <div id="manageReportContent" style="display: none; margin-top: 20px; border-top: 1px solid var(--border-color); padding-top: 20px;"></div>
      </div>
    </div>
  </main>

  <!-- FOUND THIS ITEM MODAL (REPORT FOUND FROM LOST CARD) -->
  <div id="foundThisModal" class="modal-overlay">
    <div class="modal-card claim-modal-card recovery-request-card">
      <button class="modal-close-btn" onclick="closeFoundThisModal()">&times;</button>
      <p class="section-eyebrow">Help reunite an item</p>
      <h3 class="recovery-form-title">Submit a recovery request</h3>
      <p id="foundThisSubtitle" class="recovery-form-subtitle">Share when and where you found this item. The owner will review your request using their private report dashboard.</p>
      
      <form id="foundThisForm" class="claim-form" onsubmit="handleFoundThisSubmit(event)">
        <div class="recovery-fields-grid">
          <div class="input-group"><label for="foundThisName">Full Name *</label><input type="text" id="foundThisName" maxlength="150" autocomplete="name" required></div>
          <div class="input-group"><label for="foundThisPhone">Contact Number *</label><input type="tel" id="foundThisPhone" maxlength="40" autocomplete="tel" required></div>
          <div class="input-group"><label for="foundThisEmail">Email Address</label><input type="email" id="foundThisEmail" maxlength="254" autocomplete="email"></div>
          <div class="input-group"><label for="foundThisLocation">Location Found *</label><input type="text" id="foundThisLocation" maxlength="255" placeholder="e.g. Cloud 9 boardwalk" required></div>
          <div class="input-group"><label for="foundThisDateTime">Date and Time Found *</label><input type="datetime-local" id="foundThisDateTime" required></div>
          <div class="input-group recovery-photo-field"><label for="foundThisPhoto">Photograph (optional, max 5 MB)</label><input type="file" id="foundThisPhoto" accept="image/jpeg,image/png,image/webp,image/gif"></div>
        </div>
        <div class="input-group"><label for="foundThisDetails">Additional Details *</label><textarea id="foundThisDetails" required maxlength="5000" rows="4" placeholder="Describe the item's condition and any useful details about where it was found."></textarea></div>
        <label class="recovery-consent"><input type="checkbox" id="foundThisConsent" required><span>I confirm these details are accurate and agree that the owner may use the contact details I provided to follow up.</span></label>
        <p class="recovery-privacy-note">Your phone number and email are shared only with the person who has the private management code for this lost report. No automatic SMS or email is sent.</p>
        <button type="submit" class="claim-submit-btn found-btn" id="recoverySubmitBtn">Submit Recovery Request</button>
      </form>
    </div>
  </div>

  <!-- OWNER-ONLY RECOVERY REQUEST DETAILS -->
  <div id="recoveryRequestModal" class="modal-overlay">
    <div class="modal-card recovery-details-card">
      <button class="modal-close-btn" onclick="closeRecoveryRequestModal()" aria-label="Close recovery request">&times;</button>
      <div id="recoveryRequestDetails"></div>
    </div>
  </div>

  <!-- DETAILS MODAL -->
  <div id="detailsModal" class="modal-overlay">
    <div class="modal-card" style="max-width: 540px; text-align: left;">
      <button class="modal-close-btn" onclick="closeDetailsModal()">&times;</button>
      <div id="detailsModalBody"></div>
    </div>
  </div>

  <!-- SUCCESS MODAL -->
  <div id="successModal" class="modal-overlay">
    <div class="modal-card" style="max-width: 520px;">
      <h3 id="successModalHeader" style="font-family: 'Playfair Display', serif; font-size: 24px; margin-bottom: 8px;">Report Published!</h3>
      <div id="managementCodeDisplaySection" style="display: none;">
        <p style="margin-bottom: 8px; font-weight: 600;">🔒 Your Private Management Code</p>
        <div class="code-display-box">
          <div class="code-value" id="generatedCodeValue">SF-XXXXXX</div>
          <button type="button" class="btn-copy-code" onclick="copyManagementCode()">Copy Code</button>
        </div>
      </div>
      <p id="successModalText" style="font-size: 14px; color: var(--text-muted); margin-bottom: 24px;">Your report has been saved successfully.</p>
      <button class="submit-btn found-btn" onclick="closeModal()">OK</button>
    </div>
  </div>

  <!-- DETAILED CLAIM VERIFICATION MODAL -->
  <div id="claimModal" class="modal-overlay">
    <div class="modal-card claim-modal-card">
      <button class="modal-close-btn" onclick="closeClaimModal()">&times;</button>
      <div class="claim-item-summary">
        <img id="claimModalImg" class="claim-item-img" src="" alt="Claim Item" style="display:none;">
        <div class="claim-item-details">
          <h2 id="claimModalTitle" style="font-size: 22px; font-weight: 700;">Item Title</h2>
          <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Claiming item found in <span id="claimModalLocation">Siargao</span></p>
          <p style="font-size: 12px; color: var(--primary-lost); margin-top: 6px; font-weight: 600;">🔒 Ownership Verification Required: Please provide specific identifying details below.</p>
        </div>
      </div>

      <form class="claim-form" onsubmit="handleClaimSubmit(event)">
        <!-- Section A: Basic Info -->
        <h3 style="font-size:16px; font-weight:700; border-bottom:1px solid var(--border-color); padding-bottom:6px; margin-top:10px;">1. Claimant Basic Information</h3>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>Full Name *</label><input type="text" id="claimFullName" required></div>
          <div class="input-group"><label>Contact Number *</label><input type="tel" id="claimPhone" required></div>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>Email Address</label><input type="email" id="claimEmail"></div>
          <div class="input-group">
            <label>Preferred Contact Method</label>
            <select id="claimContactPref">
              <option value="phone">Phone Call / SMS</option>
              <option value="email">Email</option>
              <option value="whatsapp">WhatsApp / Viber</option>
            </select>
          </div>
        </div>

        <!-- Section B: Item Identification -->
        <h3 style="font-size:16px; font-weight:700; border-bottom:1px solid var(--border-color); padding-bottom:6px; margin-top:10px;">2. Item Identification & Ownership Details</h3>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>1. Exact Type or Brand / Model *</label><input type="text" id="claimQBrand" required placeholder="e.g. iPhone 13, Herschel wallet"></div>
          <div class="input-group"><label>2. Main Color *</label><input type="text" id="claimQColor" required placeholder="e.g. Matte Black"></div>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>3. Secondary Colors / Patterns</label><input type="text" id="claimQSecondaryColor" placeholder="e.g. Blue silicone case"></div>
          <div class="input-group"><label>4. Approximate Size</label><input type="text" id="claimQSize" placeholder="e.g. Standard smartphone size"></div>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>5. Scratches, Dents, Cracks or Damage</label><input type="text" id="claimQDamage" placeholder="e.g. Small scratch near bottom speaker"></div>
          <div class="input-group"><label>6. Unique Marks, Stickers, or Features</label><input type="text" id="claimQUniqueMarks" placeholder="e.g. Surfing sticker on back"></div>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>7. Accessories or Components</label><input type="text" id="claimQAccessories" placeholder="e.g. Attached lanyard"></div>
          <div class="input-group"><label>8. Contents Inside (if applicable)</label><input type="text" id="claimQContents" placeholder="e.g. Driver license and 2 cards"></div>
        </div>
        <div class="input-group">
          <label>9. Specific Secret Detail to Prove Ownership *</label>
          <input type="text" id="claimQSpecificDetail" required placeholder="e.g. Lock screen photo is a sunset at General Luna">
        </div>

        <!-- Section C: Loss Information -->
        <h3 style="font-size:16px; font-weight:700; border-bottom:1px solid var(--border-color); padding-bottom:6px; margin-top:10px;">3. Loss Circumstances</h3>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>1. Where do you believe you lost it? *</label><input type="text" id="claimLossLocation" required placeholder="e.g. Cloud 9 beach area"></div>
          <div class="input-group"><label>2. When did you lose it (Approx. Date) *</label><input type="date" id="claimLossDate" required></div>
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div class="input-group"><label>3. What were you doing when lost?</label><input type="text" id="claimLossActivity" placeholder="e.g. Walking along the shore"></div>
          <div class="input-group"><label>4. When did you last remember having it?</label><input type="text" id="claimLossLastRemembered" placeholder="e.g. Around 4:00 PM yesterday"></div>
        </div>
        <div class="input-group">
          <label>5. Other circumstances surrounding loss</label>
          <textarea id="claimLossCircumstances" rows="2" placeholder="Any additional context..."></textarea>
        </div>

        <!-- Section D: Supporting Evidence -->
        <h3 style="font-size:16px; font-weight:700; border-bottom:1px solid var(--border-color); padding-bottom:6px; margin-top:10px;">4. Supporting Evidence (Optional)</h3>
        <div class="input-group">
          <label>Proof of Ownership / Old Photo URL or Reference</label>
          <input type="text" id="claimProofImg" placeholder="Optional link or photo filename of item before loss">
        </div>

        <button type="submit" class="claim-submit-btn">Submit Verification Claim</button>
      </form>
    </div>
  </div>

  <!-- FOOTER -->
  <footer>
    <div class="footer-col" style="display:flex; gap:16px;">
      <a onclick="showPage('lostPage', 'lostNav')" style="cursor:pointer; color:var(--text-muted);">Lost Items</a>
      <a onclick="showPage('reportLostPage', 'reportLostNav')" style="cursor:pointer; color:var(--text-muted);">Report Lost</a>
      <a onclick="showPage('foundPage', 'foundNav')" style="cursor:pointer; color:var(--text-muted);">Found Items</a>
      <a onclick="showPage('reportFoundPage', 'reportFoundNav')" style="cursor:pointer; color:var(--text-muted);">Report Found</a>
      <a onclick="showPage('managePage', 'manageNav')" style="cursor:pointer; color:var(--text-muted);">Manage Report</a>
    </div>
    <div class="footer-center" style="font-weight: 800; font-size: 18px;">
      Siargao<span class="red-text">Lost</span>&<span class="green-text">Found</span>
    </div>
    <div class="footer-col">
      <p style="color: var(--text-muted);">Community Hotline: 0922-123-4567</p>
    </div>
  </footer>

  <!-- JAVASCRIPT & ANIMATION BRIDGE -->
  <script>
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    let lostItems = <?php echo json_encode($lostItemsPHP); ?>;
    let foundItems = <?php echo json_encode($foundItemsPHP); ?>;
    
    let currentLostImageData = "";
    let currentFoundImageData = "";
    let currentClaimingItemId = null;
    let currentFoundThisLostItem = null;
    let selectedLocations = { lost: null, found: null };
    const locationSearchTimers = { lost: null, found: null };
    const locationSearchControllers = { lost: null, found: null };
    const locationSearchSequence = { lost: 0, found: 0 };

    let lostCurrentPage = 1;
    let foundCurrentPage = 1;
    const itemsPerPage = 8;

    function showPage(pageId, navId) {
      document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active-page');
        p.style.display = 'none';
      });
      const target = document.getElementById(pageId);
      if (target) {
        target.style.display = 'block';
        setTimeout(() => target.classList.add('active-page'), 10);
      }
      document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
      if (navId) {
        const nav = document.getElementById(navId);
        if (nav) nav.classList.add('active');
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function filterLostItems() {
      lostCurrentPage = 1;
      renderLostItems();
    }

    function renderLostItems() {
      const grid = document.getElementById('lostItemsGrid');
      const pagination = document.getElementById('lostPagination');
      const search = document.getElementById('searchLostInput').value.toLowerCase();
      const cat = document.getElementById('filterCategoryLost').value;
      const sort = document.getElementById('sortLostDate').value;

      let filtered = lostItems.filter(item => {
        const matchesSearch = item.title.toLowerCase().includes(search) || 
                              item.details.toLowerCase().includes(search) || 
                              (item.location.name && item.location.name.toLowerCase().includes(search));
        const matchesCat = (cat === 'all' || item.category === cat);
        return matchesSearch && matchesCat;
      });

      filtered.sort((a, b) => {
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        return sort === 'newest' ? dateB - dateA : dateA - dateB;
      });

      const totalPages = Math.ceil(filtered.length / itemsPerPage) || 1;
      if (lostCurrentPage > totalPages) lostCurrentPage = totalPages;
      const paginated = filtered.slice((lostCurrentPage - 1) * itemsPerPage, lostCurrentPage * itemsPerPage);

      grid.innerHTML = '';
      if (!paginated.length) {
        grid.innerHTML = '<p style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px 0;">No matching lost items found.</p>';
        pagination.innerHTML = '';
        return;
      }

      paginated.forEach((item, index) => {
        const card = document.createElement('div');
        card.className = 'item-card';
        card.style.animationDelay = `${index * 0.04}s`;
        card.innerHTML = `
          <div class="item-img-placeholder">${item.image ? `<img src="${item.image}">` : '<span>No Image</span>'}</div>
          <div class="item-body">
            <span class="item-category-badge">${escapeHTML(item.category)}</span>
            <div class="item-title">${escapeHTML(item.title)}</div>
            <div class="item-meta"><strong>By:</strong> ${escapeHTML(item.name)}<br><strong>Date:</strong> ${escapeHTML(item.date)}</div>
            <div class="item-location">📍 ${escapeHTML(item.location.name || 'Siargao')}</div>
            <div class="item-actions">
              <button class="btn-found-this" onclick='openFoundThisModal(${item.id}, ${JSON.stringify(item.title)})'>Found This Item</button>
              <button class="item-details-btn" onclick='openDetailsModal(${JSON.stringify(item)})'>View Details</button>
            </div>
          </div>
        `;
        grid.appendChild(card);
      });

      renderPagination(pagination, lostCurrentPage, totalPages, (page) => {
        lostCurrentPage = page;
        renderLostItems();
      });
    }

    function filterFoundItems() {
      foundCurrentPage = 1;
      renderFoundItems();
    }

    function renderFoundItems() {
      const grid = document.getElementById('foundItemsGrid');
      const pagination = document.getElementById('foundPagination');
      const search = document.getElementById('searchFoundInput').value.toLowerCase();
      const cat = document.getElementById('filterCategoryFound').value;
      const statusFilter = document.getElementById('filterStatusFound').value;

      let filtered = foundItems.filter(item => {
        const matchesSearch = item.title.toLowerCase().includes(search) || 
                              item.details.toLowerCase().includes(search) || 
                              (item.location.name && item.location.name.toLowerCase().includes(search));
        const matchesCat = (cat === 'all' || item.category === cat);
        
        let matchesStatus = true;
        if (statusFilter === 'active') matchesStatus = (item.status !== 'returned');
        else if (statusFilter === 'returned') matchesStatus = (item.status === 'returned');

        return matchesSearch && matchesCat && matchesStatus;
      });

      const totalPages = Math.ceil(filtered.length / itemsPerPage) || 1;
      if (foundCurrentPage > totalPages) foundCurrentPage = totalPages;
      const paginated = filtered.slice((foundCurrentPage - 1) * itemsPerPage, foundCurrentPage * itemsPerPage);

      grid.innerHTML = '';
      if (!paginated.length) {
        grid.innerHTML = '<p style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px 0;">No matching found items.</p>';
        pagination.innerHTML = '';
        return;
      }

      paginated.forEach((item, index) => {
        const card = document.createElement('div');
        card.className = 'item-card found-page-card';
        card.style.animationDelay = `${index * 0.04}s`;
        let statusBadge = '';
        if (item.status === 'in_progress') statusBadge = `<span class="status-badge status-in-progress">⏳ Verification in Progress</span>`;
        else if (item.status === 'returned') statusBadge = `<span class="status-badge status-returned">✓ Returned to Owner</span>`;

        card.innerHTML = `
          <div class="item-img-placeholder">${item.image ? `<img src="${item.image}">` : '<span>No Image</span>'}</div>
          <div class="item-body">
            ${statusBadge}
            <span class="item-category-badge">${escapeHTML(item.category)}</span>
            <div class="item-title">${escapeHTML(item.title)}</div>
            <div class="item-meta"><strong>Found by:</strong> ${escapeHTML(item.name)}<br><strong>Date:</strong> ${escapeHTML(item.date)}</div>
            <div class="item-location">📍 ${escapeHTML(item.location.name || 'Siargao')}</div>
            <div class="item-actions">
              ${item.status !== 'returned' ? `<button class="btn-contact-claimer" onclick='openClaimModal(${item.id},${JSON.stringify(item.title)}, ${JSON.stringify(item.location.name)},${JSON.stringify(item.image)})'>Claim This Item</button>` : ''}
              <button class="item-details-btn" onclick='openDetailsModal(${JSON.stringify(item)})'>View Details</button>
            </div>
          </div>
        `;
        grid.appendChild(card);
      });

      renderPagination(pagination, foundCurrentPage, totalPages, (page) => {
        foundCurrentPage = page;
        renderFoundItems();
      });
    }

    function renderPagination(container, currentPage, totalPages, callback) {
      container.innerHTML = '';
      if (totalPages <= 1) return;

      const prevBtn = document.createElement('button');
      prevBtn.className = 'pagination-btn';
      prevBtn.textContent = 'Previous';
      prevBtn.disabled = (currentPage === 1);
      prevBtn.onclick = () => callback(currentPage - 1);
      container.appendChild(prevBtn);

      for (let i = 1; i <= totalPages; i++) {
        const pageBtn = document.createElement('button');
        pageBtn.className = `pagination-btn ${i === currentPage ? 'active' : ''}`;
        pageBtn.textContent = i;
        pageBtn.onclick = () => callback(i);
        container.appendChild(pageBtn);
      }

      const nextBtn = document.createElement('button');
      nextBtn.className = 'pagination-btn';
      nextBtn.textContent = 'Next';
      nextBtn.disabled = (currentPage === totalPages);
      nextBtn.onclick = () => callback(currentPage + 1);
      container.appendChild(nextBtn);
    }

    function getLocationValue(type) {
      const input = document.getElementById(type === 'lost' ? 'lostLocationSearch' : 'foundLocationSearch');
      const typedValue = input.value.trim();
      const selected = selectedLocations[type];
      if (selected && selected.name === typedValue) return selected;
      return { name: typedValue || 'Siargao', address: typedValue || 'Siargao' };
    }

    async function handleLostSubmit(e) {
      e.preventDefault();
      const btn = document.getElementById('lostSubmitBtn');
      btn.disabled = true;
      btn.textContent = 'Publishing...';

      const formData = new FormData();
      formData.append('action', 'report_lost');
      formData.append('category', document.getElementById('itemCategory').value);
      formData.append('title', document.getElementById('itemTitle').value);
      formData.append('details', document.getElementById('itemDetails').value);
      formData.append('name', document.getElementById('fullName').value);
      formData.append('address', document.getElementById('address').value);
      formData.append('phone', document.getElementById('phoneNumber').value);
      formData.append('email', document.getElementById('email').value);
      const location = getLocationValue('lost');
      formData.append('location_name', location.name);
      formData.append('location_address', location.address);
      formData.append('image_data', currentLostImageData);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
          lostItems.unshift(data.item);
          renderLostItems();
          document.getElementById('successModalHeader').textContent = "Lost Report Published!";
          document.getElementById('managementCodeDisplaySection').style.display = 'block';
          document.getElementById('generatedCodeValue').textContent = data.management_code;
          document.getElementById('successModalText').textContent = "Your lost report is live. Save your private code to review recovery requests and manage the report.";
          document.getElementById('successModal').classList.add('active');
          document.getElementById('lostForm').reset();
          resetLocation('lost');
          resetImagePreview('uploadBoxLost', 'lost');
        } else {
          alert(data.message || 'Error submitting report.');
        }
      } catch (err) {
        alert('Network or server error occurred.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Publish Lost Report';
      }
    }

    async function handleFoundSubmit(e) {
      e.preventDefault();
      const btn = document.getElementById('foundSubmitBtn');
      btn.disabled = true;
      btn.textContent = 'Publishing...';

      const formData = new FormData();
      formData.append('action', 'report_found');
      formData.append('category', document.getElementById('foundItemCategory').value);
      formData.append('title', document.getElementById('foundItemTitle').value);
      formData.append('details', document.getElementById('foundItemDetails').value);
      formData.append('name', document.getElementById('foundFullName').value);
      formData.append('phone', document.getElementById('foundPhoneNumber').value);
      formData.append('email', document.getElementById('foundEmail').value);
      const location = getLocationValue('found');
      formData.append('location_name', location.name);
      formData.append('location_address', location.address);
      formData.append('image_data', currentFoundImageData);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
          foundItems.unshift(data.item);
          renderFoundItems();
          document.getElementById('successModalHeader').textContent = "Found Report Published!";
          document.getElementById('managementCodeDisplaySection').style.display = 'block';
          document.getElementById('generatedCodeValue').textContent = data.management_code;
          document.getElementById('successModalText').textContent = "Save your private management code to review claims and manage this report.";
          document.getElementById('successModal').classList.add('active');
          document.getElementById('foundForm').reset();
          resetLocation('found');
          resetImagePreview('uploadBoxFound', 'found');
        } else {
          alert(data.message || 'Error submitting found report.');
        }
      } catch (err) {
        alert('Network or server error occurred.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Publish Found Report';
      }
    }

    function openFoundThisModal(lostId, lostTitle) {
      currentFoundThisLostItem = lostItems.find(i => i.id === lostId);
      if (!currentFoundThisLostItem) return;
      document.getElementById('foundThisSubtitle').textContent = `Submitting a recovery request for: "${lostTitle}"`;
      document.getElementById('foundThisModal').classList.add('active');
    }

    function closeFoundThisModal() {
      document.getElementById('foundThisModal').classList.remove('active');
      currentFoundThisLostItem = null;
    }

    async function handleFoundThisSubmit(e) {
      e.preventDefault();
      if (!currentFoundThisLostItem) return;

      const btn = document.getElementById('recoverySubmitBtn');
      btn.disabled = true;
      btn.textContent = 'Sending request...';
      const formData = new FormData();
      formData.append('action', 'submit_recovery_request');
      formData.append('item_id', currentFoundThisLostItem.id);
      formData.append('finder_name', document.getElementById('foundThisName').value);
      formData.append('finder_phone', document.getElementById('foundThisPhone').value);
      formData.append('finder_email', document.getElementById('foundThisEmail').value);
      formData.append('location_found', document.getElementById('foundThisLocation').value);
      formData.append('found_at', document.getElementById('foundThisDateTime').value);
      formData.append('additional_details', document.getElementById('foundThisDetails').value);
      formData.append('confirmation', document.getElementById('foundThisConsent').checked ? 'yes' : '');
      const evidenceFile = document.getElementById('foundThisPhoto').files[0];
      if (evidenceFile) formData.append('evidence_image', evidenceFile);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
          closeFoundThisModal();
          document.getElementById('foundThisForm').reset();
          document.getElementById('successModalHeader').textContent = 'Recovery Request Submitted';
          document.getElementById('managementCodeDisplaySection').style.display = 'none';
          document.getElementById('successModalText').textContent = 'Your request has been saved. The item owner can review it in their private report dashboard. No automatic SMS or email was sent.';
          document.getElementById('successModal').classList.add('active');
        } else {
          alert(data.message || 'Error submitting recovery request.');
        }
      } catch (err) {
        alert('Network or server error occurred.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Submit Recovery Request';
      }
    }

    async function handleManageReport() {
      const code = document.getElementById('managementCodeInput').value.trim();
      const err = document.getElementById('manageErrorMsg');
      const box = document.getElementById('manageReportContent');
      err.style.display = 'none'; box.style.display = 'none';

      if (!code) {
        err.textContent = 'Please enter your management code.';
        err.style.display = 'block';
        return;
      }

      const formData = new FormData();
      formData.append('action', 'manage_lookup');
      formData.append('management_code', code);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();

        if (!data.success) {
          err.textContent = data.message;
          err.style.display = 'block';
          return;
        }

        const item = data.item;
        const recoveryRequests = data.recovery_requests || [];
        const unreadRecoveryCount = Number(data.unread_recovery_count || 0);
        const recoveryHTML = item.item_type === 'lost' ? `
          <section class="recovery-dashboard-section" aria-labelledby="recoveryDashboardTitle">
            <div class="recovery-dashboard-heading">
              <div><p class="section-eyebrow">Owner dashboard</p><h4 id="recoveryDashboardTitle">Recovery requests</h4></div>
              <span class="recovery-unread-badge" id="recoveryUnreadBadge" style="${unreadRecoveryCount ? '' : 'display:none;'}">${unreadRecoveryCount} new</span>
            </div>
            ${recoveryRequests.length ? `<div class="recovery-request-list">${recoveryRequests.map(request => `
              <article class="recovery-request-row ${request.unread ? 'is-unread' : ''}" id="recoveryRequestRow${request.id}">
                <div class="recovery-request-row-main">
                  <div class="recovery-request-row-meta">
                    <span class="recovery-status-pill">${escapeHTML(request.status)}</span>
                    <span class="recovery-new-indicator" id="recoveryNewIndicator${request.id}" style="${request.unread ? '' : 'display:none;'}">New</span>
                  </div>
                  <h5>${escapeHTML(request.finder_name)}</h5>
                  <p>Found at ${escapeHTML(request.location_found)} · ${escapeHTML(request.found_at)}</p>
                  <span class="recovery-submitted-date">Submitted ${escapeHTML(request.submitted_at)}</span>
                </div>
                <button type="button" class="recovery-view-button" onclick="openRecoveryRequest(${request.id}, ${item.id})">View details <span aria-hidden="true">→</span></button>
              </article>
            `).join('')}</div>` : '<div class="recovery-empty-state"><span aria-hidden="true">✦</span><p>No recovery requests yet. New requests for this lost report will appear here.</p></div>'}
          </section>
        ` : '';
        let claimsHTML = !item.claims.length ? '<p style="color:var(--text-muted); font-size:14px;">No claims submitted yet.</p>' : item.claims.map(c => {
          let parsedData = {};
          try { parsedData = JSON.parse(c.reason); } catch(e) { parsedData = { specific_detail: c.reason }; }
          
          return `
            <div class="claim-item-card">
              <p><strong>Claimant:</strong> ${escapeHTML(c.full_name)} (${escapeHTML(c.email || 'No email')}) - Phone: ${escapeHTML(c.phone)}</p>
              
              <!-- ADMIN COMPARISON VIEW -->
              <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:10px; background:#fff; padding:12px; border-radius:6px; border:1px solid var(--border-color);">
                <div>
                  <h5 style="color:var(--primary-found); font-size:12px; text-transform:uppercase; margin-bottom:4px;">Original Found Report</h5>
                  <p style="font-size:12px;"><strong>Title:</strong> ${escapeHTML(item.title)}</p>
                  <p style="font-size:12px;"><strong>Category:</strong> ${escapeHTML(item.category)}</p>
                  <p style="font-size:12px;"><strong>Description:</strong> ${escapeHTML(item.details)}</p>
                  <p style="font-size:12px;"><strong>Location Found:</strong> ${escapeHTML(item.location.name)}</p>
                </div>
                <div>
                  <h5 style="color:var(--primary-lost); font-size:12px; text-transform:uppercase; margin-bottom:4px;">Claimant Verification Answers</h5>
                  <p style="font-size:12px;"><strong>Brand/Model:</strong> ${escapeHTML(parsedData.brand || 'N/A')}</p>
                  <p style="font-size:12px;"><strong>Color:</strong> ${escapeHTML(parsedData.color || 'N/A')}</p>
                  <p style="font-size:12px;"><strong>Damage/Marks:</strong> ${escapeHTML(parsedData.damage || 'N/A')} / ${escapeHTML(parsedData.unique_marks || 'N/A')}</p>
                  <p style="font-size:12px;"><strong>Secret Detail:</strong> <span style="background:#FEF3C7; padding:2px 4px; font-weight:700;">${escapeHTML(parsedData.specific_detail || 'N/A')}</span></p>
                  <p style="font-size:12px;"><strong>Loss Location/Date:</strong> ${escapeHTML(parsedData.loss_location || 'N/A')} (${escapeHTML(parsedData.loss_date || 'N/A')})</p>
                </div>
              </div>

              <p style="margin-top:8px; font-size:13px;"><strong>Status:</strong> <span style="text-transform:uppercase; font-weight:700; font-size:12px; color:var(--primary-lost);">${escapeHTML(c.status)}</span></p>
              
              <div class="claim-actions" style="flex-wrap: wrap;">
                <button class="btn-approve" onclick="updateClaim(${c.id}, 'Approved', ${item.id})">Approve Claim</button>
                <button class="btn-reject" onclick="promptRejectClaim(${c.id}, ${item.id})">Reject Claim</button>
                <button class="pagination-btn" style="background:#F8FAFC;" onclick="updateClaim(${c.id}, 'Additional Information Required', ${item.id})">Request Info</button>
              </div>
            </div>
          `;
        }).join('');

        box.innerHTML = `
          <div class="manage-card">
            <h3 style="font-size:18px; font-weight:700; margin-bottom:6px;">${escapeHTML(item.title)}</h3>
            <p style="color:var(--text-muted); font-size:14px;">Current Status: <strong style="text-transform:uppercase; color:var(--text-main);">${escapeHTML(item.status)}</strong></p>
            ${item.item_type === 'found' && item.status !== 'returned' ? `<button class="submit-btn found-btn" style="width:auto; padding:10px 20px; font-size:13px; margin-top:14px;" onclick="markReturned(${item.id})">Mark as Returned to Owner</button>` : ''}
            ${item.item_type === 'found' && item.status === 'returned' ? `<p style="color:var(--primary-found); font-weight:700; margin-top:10px;">Item successfully marked as returned.</p><button type="button" class="btn-reject" style="margin-top:14px;" onclick="deleteReturnedFoundItem(${item.id})">Remove this item</button>` : ''}
          </div>
          ${recoveryHTML}
          ${item.item_type === 'found' ? `<h4 style="font-size:16px; font-weight:700; margin-bottom:8px;">Submitted Claims & Verification (${item.claims.length})</h4>${claimsHTML}` : ''}
        `;
        box.style.display = 'block';
      } catch (err) {
        err.textContent = 'Server connection error during lookup.';
        err.style.display = 'block';
      }
    }

    function updateRecoveryNotificationBadge(unreadCount, requestId = null) {
      const badge = document.getElementById('recoveryUnreadBadge');
      if (badge) {
        badge.textContent = `${unreadCount} new`;
        badge.style.display = unreadCount > 0 ? 'inline-flex' : 'none';
      }
      if (requestId !== null) {
        const row = document.getElementById(`recoveryRequestRow${requestId}`);
        const indicator = document.getElementById(`recoveryNewIndicator${requestId}`);
        if (row) row.classList.remove('is-unread');
        if (indicator) indicator.style.display = 'none';
      }
    }

    async function openRecoveryRequest(requestId, itemId) {
      const formData = new FormData();
      formData.append('action', 'get_recovery_request');
      formData.append('request_id', requestId);
      formData.append('item_id', itemId);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (!data.success) {
          alert(data.message || 'Could not open this recovery request.');
          return;
        }

        const request = data.request;
        const phoneHref = (request.finder_phone || '').replace(/[^+\d]/g, '');
        const statusOptions = ['New Request', 'Under Review', 'Contact Established', 'Verification in Progress', 'Successfully Returned', 'Rejected'];
        const optionsHTML = statusOptions.map(status => `<option value="${escapeHTML(status)}" ${request.status === status ? 'selected' : ''}>${escapeHTML(status)}</option>`).join('');
        const evidenceHTML = request.evidence_image ? `<div class="recovery-evidence"><h4>Finder photograph</h4><img src="${escapeHTML(request.evidence_image)}" alt="Photograph submitted by the finder"></div>` : '';

        document.getElementById('recoveryRequestDetails').innerHTML = `
          <p class="section-eyebrow">Recovery request #${request.id}</p>
          <h2 class="recovery-detail-title">${escapeHTML(request.item_title)}</h2>
          <p class="recovery-detail-subtitle">Submitted ${escapeHTML(request.submitted_at)}</p>
          <div class="recovery-detail-summary">
            <div><span>Finder</span><strong>${escapeHTML(request.finder_name)}</strong></div>
            <div><span>Location found</span><strong>${escapeHTML(request.location_found)}</strong></div>
            <div><span>Date and time found</span><strong>${escapeHTML(request.found_at)}</strong></div>
            <div><span>Confirmation</span><strong>${request.confirmation_accepted ? 'Finder confirmed the details' : 'Not confirmed'}</strong></div>
          </div>
          <div class="recovery-detail-block"><h4>Additional details</h4><p>${escapeHTML(request.additional_details).replace(/\n/g, '<br>')}</p></div>
          <div class="recovery-contact-panel">
            <div><p class="section-eyebrow">Private finder contact</p><h3>${escapeHTML(request.finder_name)}</h3><p>${escapeHTML(request.finder_phone)}</p>${request.finder_email ? `<p>${escapeHTML(request.finder_email)}</p>` : '<p>No email address supplied</p>'}</div>
            <div class="recovery-contact-actions"><a href="tel:${escapeHTML(phoneHref)}">Call finder</a>${request.finder_email ? `<a href="mailto:${escapeHTML(request.finder_email)}">Email finder</a>` : ''}</div>
          </div>
          ${evidenceHTML}
          <div class="recovery-status-editor">
            <div><span>Request status</span><strong id="recoveryDetailStatus">${escapeHTML(request.status)}</strong></div>
            <select id="recoveryStatusSelect" aria-label="Recovery request status">${optionsHTML}</select>
            <button type="button" class="submit-btn found-btn" onclick="saveRecoveryRequestStatus(${request.id}, ${request.item_id})">Save status</button>
          </div>
        `;
        updateRecoveryNotificationBadge(data.unread_recovery_count, request.id);
        document.getElementById('recoveryRequestModal').classList.add('active');
      } catch (err) {
        alert('Server connection error while loading this recovery request.');
      }
    }

    function closeRecoveryRequestModal() {
      document.getElementById('recoveryRequestModal').classList.remove('active');
    }

    async function saveRecoveryRequestStatus(requestId, itemId) {
      const formData = new FormData();
      formData.append('action', 'update_recovery_status');
      formData.append('request_id', requestId);
      formData.append('item_id', itemId);
      formData.append('status', document.getElementById('recoveryStatusSelect').value);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (!data.success) {
          alert(data.message || 'Could not update this recovery request.');
          return;
        }
        document.getElementById('recoveryDetailStatus').textContent = document.getElementById('recoveryStatusSelect').value;
        updateRecoveryNotificationBadge(data.unread_recovery_count);
        await handleManageReport();
      } catch (err) {
        alert('Server connection error while updating this recovery request.');
      }
    }

    async function updateClaim(claimId, status, itemId, rejectionReason = '') {
      const formData = new FormData();
      formData.append('action', 'update_claim');
      formData.append('claim_id', claimId);
      formData.append('status', status);
      formData.append('item_id', itemId);
      formData.append('rejection_reason', rejectionReason);
      formData.append('csrf_token', csrfToken);

      const res = await fetch('', { method: 'POST', body: formData });
      const data = await res.json();
      if (data.success) {
        handleManageReport();
        renderFoundItems();
      } else {
        alert(data.message || 'Action unauthorized or failed.');
      }
    }

    function promptRejectClaim(claimId, itemId) {
      const reason = prompt('Please enter a mandatory reason for rejecting this claim:');
      if (reason && reason.trim() !== '') {
        updateClaim(claimId, 'Rejected', itemId, reason.trim());
      } else if (reason !== null) {
        alert('Rejection reason is required.');
      }
    }

    async function markReturned(itemId) {
      const formData = new FormData();
      formData.append('action', 'mark_returned');
      formData.append('item_id', itemId);
      formData.append('csrf_token', csrfToken);

      const res = await fetch('', { method: 'POST', body: formData });
      const data = await res.json();
      if (data.success) {
        handleManageReport();
        renderFoundItems();
      } else {
        alert(data.message || 'Action unauthorized or failed.');
      }
    }

    async function deleteReturnedFoundItem(itemId) {
      const confirmed = window.confirm('Permanently remove this returned item from the site? Its submitted claims will also be removed. This cannot be undone.');
      if (!confirmed) return;

      const formData = new FormData();
      formData.append('action', 'delete_returned_found');
      formData.append('item_id', itemId);
      formData.append('csrf_token', csrfToken);

      try {
        const response = await fetch('', { method: 'POST', body: formData });
        const data = await response.json();
        if (!data.success) {
          alert(data.message || 'Could not remove this returned item.');
          return;
        }

        foundItems = foundItems.filter(item => item.id !== Number(itemId));
        renderFoundItems();
        const box = document.getElementById('manageReportContent');
        box.innerHTML = '<div class="manage-card"><p>This returned item has been removed from the site.</p></div>';
        document.getElementById('managementCodeInput').value = '';
      } catch (err) {
        alert('Server connection error while removing this item.');
      }
    }

    function openDetailsModal(item) {
      const modalBody = document.getElementById('detailsModalBody');
      modalBody.innerHTML = `
        <div style="margin-bottom:16px;">
          ${item.image ? `<img src="${item.image}" style="width:100%; height:200px; object-fit:cover; border-radius:var(--radius-sm); margin-bottom:12px;">` : ''}
          <span class="item-category-badge">${escapeHTML(item.category)}</span>
          <h3 style="font-size:20px; font-weight:700; margin-top:4px;">${escapeHTML(item.title)}</h3>
        </div>
        <div style="font-size:14px; color:var(--text-muted); display:flex; flex-direction:column; gap:8px;">
          <p><strong>Description:</strong> ${escapeHTML(item.details)}</p>
          <p><strong>Reported By:</strong> ${escapeHTML(item.name)}</p>
          <p><strong>Date Reported:</strong> ${escapeHTML(item.date)} at ${escapeHTML(item.time || '')}</p>
          <p><strong>Location:</strong> ${escapeHTML(item.location.name || 'Siargao')}</p>
          <p><strong>Status:</strong> <span style="text-transform:uppercase; font-weight:700;">${escapeHTML(item.status)}</span></p>
        </div>
      `;
      document.getElementById('detailsModal').classList.add('active');
    }

    function closeDetailsModal() {
      document.getElementById('detailsModal').classList.remove('active');
    }

    function openClaimModal(id, title, location, img) {
      currentClaimingItemId = id;
      document.getElementById('claimModalTitle').textContent = title;
      document.getElementById('claimModalLocation').textContent = location || 'Siargao';
      const imgElem = document.getElementById('claimModalImg');
      if (img && img !== 'undefined' && img !== 'null') { 
        imgElem.src = img; 
        imgElem.style.display = 'block'; 
      } else {
        imgElem.style.display = 'none';
      }
      document.getElementById('claimModal').classList.add('active');
    }

    function closeClaimModal() {
      document.getElementById('claimModal').classList.remove('active');
    }

    async function handleClaimSubmit(e) {
      e.preventDefault();
      const formData = new FormData();
      formData.append('action', 'submit_claim');
      formData.append('item_id', currentClaimingItemId);
      formData.append('full_name', document.getElementById('claimFullName').value);
      formData.append('email', document.getElementById('claimEmail').value);
      formData.append('phone', document.getElementById('claimPhone').value);
      formData.append('contact_pref', document.getElementById('claimContactPref').value);
      
      formData.append('q_brand', document.getElementById('claimQBrand').value);
      formData.append('q_color', document.getElementById('claimQColor').value);
      formData.append('q_secondary_color', document.getElementById('claimQSecondaryColor').value);
      formData.append('q_size', document.getElementById('claimQSize').value);
      formData.append('q_damage', document.getElementById('claimQDamage').value);
      formData.append('q_unique_marks', document.getElementById('claimQUniqueMarks').value);
      formData.append('q_accessories', document.getElementById('claimQAccessories').value);
      formData.append('q_contents', document.getElementById('claimQContents').value);
      formData.append('q_specific_detail', document.getElementById('claimQSpecificDetail').value);

      formData.append('loss_location', document.getElementById('claimLossLocation').value);
      formData.append('loss_date', document.getElementById('claimLossDate').value);
      formData.append('loss_activity', document.getElementById('claimLossActivity').value);
      formData.append('loss_last_remembered', document.getElementById('claimLossLastRemembered').value);
      formData.append('loss_circumstances', document.getElementById('claimLossCircumstances').value);
      formData.append('proof_img', document.getElementById('claimProofImg').value);
      formData.append('csrf_token', csrfToken);

      try {
        const res = await fetch('', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
          alert("Detailed ownership verification claim submitted successfully! Status is now Pending Verification.");
          closeClaimModal();
          // Reset form
          e.target.reset();
        } else {
          alert(data.message || 'Failed to submit verification claim.');
        }
      } catch (err) {
        alert('Network error while submitting claim.');
      }
    }

    function previewImage(e, type) {
      const input = e.target;
      if (input.files && input.files[0]) {
        const file = input.files[0];
        if (file.size > 5 * 1024 * 1024) {
          alert('Image size exceeds 5MB limit.');
          input.value = '';
          return;
        }

        const reader = new FileReader();
        reader.onload = function(evt) {
          const result = evt.target.result;
          if (type === 'lost') {
            currentLostImageData = result;
          } else {
            currentFoundImageData = result;
          }

          const boxId = type === 'lost' ? 'uploadBoxLost' : 'uploadBoxFound';
          const box = document.getElementById(boxId);
          let img = box.querySelector('img');
          if (!img) { img = document.createElement('img'); box.appendChild(img); }
          img.src = result;
        };
        reader.readAsDataURL(file);
      }
    }

    function resetImagePreview(boxId, type) {
      if (type === 'lost') currentLostImageData = "";
      else currentFoundImageData = "";

      const box = document.getElementById(boxId);
      if (box) { const img = box.querySelector('img'); if (img) img.remove(); }
    }

    function showLocationMessage(suggestions, message) {
      const status = document.createElement('div');
      status.className = 'location-search-message';
      status.setAttribute('role', 'status');
      status.textContent = message;
      suggestions.appendChild(status);
    }

    function selectLocation(type, location) {
      const input = document.getElementById(type === 'lost' ? 'lostLocationSearch' : 'foundLocationSearch');
      const suggestions = document.getElementById(type === 'lost' ? 'lostLocationSuggestions' : 'foundLocationSuggestions');
      const selected = document.getElementById(type === 'lost' ? 'selectedLostLocation' : 'selectedFoundLocation');

      if (locationSearchTimers[type]) clearTimeout(locationSearchTimers[type]);
      if (locationSearchControllers[type]) locationSearchControllers[type].abort();
      locationSearchSequence[type] += 1;

      selectedLocations[type] = location;
      input.value = location.name;
      selected.textContent = `Location selected: ${location.name}`;
      suggestions.replaceChildren();
      suggestions.classList.remove('active');
    }

    function addTypedLocationOption(type, suggestions, query) {
      const option = document.createElement('button');
      option.type = 'button';
      option.className = 'location-suggestion';
      option.innerHTML = `<strong>Use typed location</strong><small>${escapeHTML(query)}</small>`;
      option.addEventListener('click', () => selectLocation(type, {
        name: query,
        address: query,
        source: 'typed'
      }));
      suggestions.appendChild(option);
    }

    async function searchLocation(type) {
      const input = document.getElementById(type === 'lost' ? 'lostLocationSearch' : 'foundLocationSearch');
      const suggestions = document.getElementById(type === 'lost' ? 'lostLocationSuggestions' : 'foundLocationSuggestions');
      const selected = document.getElementById(type === 'lost' ? 'selectedLostLocation' : 'selectedFoundLocation');
      const query = input.value.trim();

      if (locationSearchTimers[type]) clearTimeout(locationSearchTimers[type]);
      if (locationSearchControllers[type]) locationSearchControllers[type].abort();
      locationSearchControllers[type] = null;
      const requestId = ++locationSearchSequence[type];

      if (!query) {
        selectedLocations[type] = null;
        selected.textContent = 'No location selected yet.';
        suggestions.replaceChildren();
        suggestions.classList.remove('active');
        return;
      }

      // Typed locations remain valid even if the geocoder is unavailable or has no match.
      selectedLocations[type] = { name: query, address: query, source: 'typed' };
      selected.textContent = `Using typed location: ${query}`;

      if (query.length < 2) {
        suggestions.replaceChildren();
        suggestions.classList.remove('active');
        return;
      }

      suggestions.replaceChildren();
      showLocationMessage(suggestions, 'Searching places...');
      addTypedLocationOption(type, suggestions, query);
      suggestions.classList.add('active');

      locationSearchTimers[type] = setTimeout(async () => {
        const controller = new AbortController();
        locationSearchControllers[type] = controller;
        const params = new URLSearchParams({
          q: `${query}, Siargao, Philippines`,
          lat: '9.85',
          lon: '126.05',
          zoom: '11',
          location_bias_scale: '0.1',
          countrycode: 'ph',
          limit: '6',
          lang: 'en'
        });

        try {
          const response = await fetch(`https://photon.komoot.io/api/?${params.toString()}`, { signal: controller.signal });
          if (!response.ok) throw new Error(`Place search failed (${response.status})`);
          const data = await response.json();
          if (requestId !== locationSearchSequence[type] || input.value.trim() !== query) return;

          suggestions.replaceChildren();
          const places = Array.isArray(data.features) ? data.features : [];
          if (!places.length) {
            showLocationMessage(suggestions, 'No matching places found. You can use the location you typed.');
          }

          places.forEach(feature => {
            const properties = feature.properties || {};
            const name = properties.name || properties.street || properties.city || properties.district || query;
            const address = [...new Set([
              properties.name,
              properties.street,
              properties.housenumber,
              properties.district,
              properties.city,
              properties.state,
              properties.country
            ].filter(Boolean))].join(', ') || name;
            const option = document.createElement('button');
            option.type = 'button';
            option.className = 'location-suggestion';
            option.innerHTML = `<strong>${escapeHTML(name)}</strong>${address !== name ? `<small>${escapeHTML(address)}</small>` : ''}`;
            option.addEventListener('click', () => selectLocation(type, {
              name,
              address,
              source: 'place'
            }));
            suggestions.appendChild(option);
          });

          addTypedLocationOption(type, suggestions, query);
        } catch (err) {
          if (err.name === 'AbortError') return;
          if (requestId !== locationSearchSequence[type]) return;
          suggestions.replaceChildren();
          showLocationMessage(suggestions, 'Place suggestions are unavailable. You can still use the location you typed.');
          addTypedLocationOption(type, suggestions, query);
        }
      }, 400);
    }

    function resetLocation(type) {
      const input = document.getElementById(type === 'lost' ? 'lostLocationSearch' : 'foundLocationSearch');
      const suggestions = document.getElementById(type === 'lost' ? 'lostLocationSuggestions' : 'foundLocationSuggestions');
      const selected = document.getElementById(type === 'lost' ? 'selectedLostLocation' : 'selectedFoundLocation');
      if (locationSearchTimers[type]) clearTimeout(locationSearchTimers[type]);
      if (locationSearchControllers[type]) locationSearchControllers[type].abort();
      locationSearchSequence[type] += 1;
      selectedLocations[type] = null;
      input.value = '';
      selected.textContent = 'No location selected yet.';
      suggestions.replaceChildren();
      suggestions.classList.remove('active');
    }

    function closeModal() { document.getElementById('successModal').classList.remove('active'); }
    function copyManagementCode() { 
      navigator.clipboard.writeText(document.getElementById('generatedCodeValue').textContent); 
      alert('Copied to clipboard!'); 
    }
    function escapeHTML(str) { return str ? String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;') : ''; }

    document.addEventListener('DOMContentLoaded', () => {
      renderLostItems();
      renderFoundItems();
    });
  </script>
</body>
</html>
