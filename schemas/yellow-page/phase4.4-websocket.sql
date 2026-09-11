-- Phase 4.4 runtime-owned WebSocket/session closure. This runs after the
-- Phase 4 Yellow Page identity/session schema and intentionally contains no
-- Hub, MFS, conference or presence dependency. `authn` retains the historical
-- OTAK storage contract; its value is resolved and consumed only by socket_bind.
-- System Drumates themselves are provisioned outside the runtime. This closure
-- resolves sys_conf.nobody_id and never creates a user, Hub or DMZ resource.

CREATE TABLE IF NOT EXISTS `authn` (
  `token` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `type` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.type')) VIRTUAL,
  `id` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.id')) VIRTUAL,
  `host` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.host')) VIRTUAL,
  `value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`value`)),
  `ctime` int(11) unsigned NOT NULL,
  PRIMARY KEY (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `socket` (
  `id` varchar(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `session_id` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `uid` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `domain_id` int(11) unsigned DEFAULT NULL,
  `ctime` int(11) unsigned NOT NULL,
  `mtime` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `socket_session` (`session_id`),
  KEY `socket_uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- e8e7bac8e predates the provisioned-principal registry. Its creation is an
-- upgrade prerequisite only; organisation provisioning remains responsible
-- for the values and the corresponding Drumates.
CREATE TABLE IF NOT EXISTS `sys_conf` (
  `conf_key` varchar(40) NOT NULL,
  `conf_value` longtext DEFAULT NULL,
  PRIMARY KEY (`conf_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

DELIMITER $
-- `CREATE TABLE IF NOT EXISTS` intentionally does not alter the Phase 4.4
-- predecessor. Apply the narrowly scoped upgrade before installing procedures
-- which reference authn.ctime. The transient authn credential has no value
-- across an upgrade, so a pre-ctime table is invalidated instead of guessed.
DROP PROCEDURE IF EXISTS `phase44_schema_upgrade`$
CREATE PROCEDURE `phase44_schema_upgrade`()
BEGIN
  DECLARE _authn_ctime int DEFAULT 0;
  DECLARE _authn_ctime_nullable varchar(3);
  DECLARE _cookie_uid_nullable varchar(3);
  DECLARE _socket_uid_nullable varchar(3);
  DECLARE _entity_type int DEFAULT 0;
  DECLARE _null_cookies int DEFAULT 0;
  DECLARE _nobody_id varchar(16) CHARACTER SET ascii;
  DECLARE _nobody_exists int DEFAULT 0;

  SELECT COUNT(*) INTO _entity_type
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'entity' AND column_name = 'type';
  IF _entity_type = 0 THEN
    ALTER TABLE entity ADD COLUMN type enum('organization','hub','drumate','shop','blog','forum','guest','dummy') DEFAULT NULL AFTER home_id;
  END IF;

  SELECT COUNT(*), MAX(IS_NULLABLE)
    INTO _authn_ctime, _authn_ctime_nullable
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'authn' AND column_name = 'ctime';
  IF _authn_ctime = 0 THEN
    DELETE FROM authn;
    ALTER TABLE authn ADD COLUMN ctime int(11) unsigned NOT NULL DEFAULT 0;
    ALTER TABLE authn MODIFY COLUMN ctime int(11) unsigned NOT NULL;
  ELSEIF _authn_ctime_nullable = 'YES' THEN
    UPDATE authn SET ctime = UNIX_TIMESTAMP() WHERE ctime IS NULL;
    ALTER TABLE authn MODIFY COLUMN ctime int(11) unsigned NOT NULL;
  END IF;

  SELECT COUNT(*) INTO _null_cookies FROM cookie WHERE uid IS NULL;
  IF _null_cookies > 0 THEN
    SELECT conf_value INTO _nobody_id FROM sys_conf WHERE conf_key = 'nobody_id' LIMIT 1;
    SELECT COUNT(*) INTO _nobody_exists
      FROM entity e INNER JOIN drumate d ON d.id = e.id
      WHERE e.id = _nobody_id;
    IF _nobody_id IS NULL OR _nobody_id = '' OR _nobody_exists = 0 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RUNTIME_NOBODY_PRINCIPAL_MISSING';
    END IF;
    UPDATE cookie SET uid = _nobody_id WHERE uid IS NULL;
  END IF;
  SELECT IS_NULLABLE INTO _cookie_uid_nullable
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'cookie' AND column_name = 'uid';
  IF _cookie_uid_nullable = 'YES' THEN
    ALTER TABLE cookie MODIFY COLUMN uid varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL;
  END IF;

  -- Socket bindings are transient connections. Preserve a recoverable UID
  -- from their persisted session, and discard only orphaned nullable rows;
  -- an old live connection must reconnect and claim a new OTAK after upgrade.
  UPDATE socket s INNER JOIN cookie c ON c.id = s.session_id
    SET s.uid = c.uid
    WHERE s.uid IS NULL AND c.uid IS NOT NULL;
  DELETE FROM socket WHERE uid IS NULL;
  SELECT IS_NULLABLE INTO _socket_uid_nullable
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'socket' AND column_name = 'uid';
  IF _socket_uid_nullable = 'YES' THEN
    ALTER TABLE socket MODIFY COLUMN uid varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL;
  END IF;
END$
CALL phase44_schema_upgrade()$
DROP PROCEDURE phase44_schema_upgrade$

DROP PROCEDURE IF EXISTS `session_ensure`$
CREATE PROCEDURE `session_ensure`(
  IN _sid varchar(64) CHARACTER SET ascii
)
BEGIN
  DECLARE _session_id varchar(64) CHARACTER SET ascii;
  DECLARE _nobody_id varchar(16) CHARACTER SET ascii;
  DECLARE _nobody_exists int DEFAULT 0;
  DECLARE _status varchar(64);
  DECLARE _mtime int unsigned;

  -- The fixed UID is the source-level invariant, but a provisioned
  -- sys_conf.nobody_id is authoritative for an installed organisation.
  SELECT COALESCE((SELECT conf_value FROM sys_conf WHERE conf_key = 'nobody_id' LIMIT 1), 'ffffffffffffffff')
    INTO _nobody_id;
  SELECT COUNT(*) INTO _nobody_exists
    FROM entity e INNER JOIN drumate d ON d.id = e.id
    WHERE e.id = _nobody_id;
  IF _nobody_exists = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RUNTIME_NOBODY_PRINCIPAL_MISSING';
  END IF;

  IF _sid IS NOT NULL AND _sid REGEXP '^[A-Za-z0-9_-]{16,64}$' THEN
    SELECT id INTO _session_id FROM cookie WHERE id = _sid LIMIT 1;
    -- Compatibility repair for historical nullable cookie.uid rows. This is
    -- deliberately NULL-only: an OTP session may carry a real Drumate UID
    -- while remaining unsigned and must never be reset here.
    IF _session_id IS NOT NULL THEN
      SELECT status, mtime INTO _status, _mtime FROM cookie WHERE id = _session_id;
      -- session_check_cookie expires the source OTP context after ten minutes
      -- and restores the anonymous principal. The minimal runtime has no OTP
      -- delivery table, so cookie.mtime is the corresponding local transition
      -- timestamp; an active OTP's real UID is otherwise left untouched.
      IF _status IN ('otp', 'otp_pending') AND _mtime < UNIX_TIMESTAMP() - 600 THEN
        UPDATE cookie SET uid = _nobody_id, ctime = UNIX_TIMESTAMP(), mtime = UNIX_TIMESTAMP(), status = 'new'
          WHERE id = _session_id;
      ELSE
        UPDATE cookie SET uid = _nobody_id WHERE id = _session_id AND uid IS NULL;
      END IF;
    END IF;
  END IF;
  IF _session_id IS NULL THEN
    SET _session_id = CONCAT(uniqueId(), uniqueId());
    INSERT INTO cookie (id, uid, ctime, mtime, ua, ttl, failed, status)
      VALUES (_session_id, _nobody_id, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 'runtime', 2592000, 0, 'new');
  END IF;
  SELECT id AS session_id, uid, status FROM cookie WHERE id = _session_id LIMIT 1;
END$

DROP PROCEDURE IF EXISTS `authn_store`$
CREATE PROCEDURE `authn_store`(
  IN _token VARCHAR(90) CHARACTER SET ascii,
  IN _value JSON
)
BEGIN
  -- Historical authn has no expiry column. The target keeps its wire/value
  -- shape but bounds the OTAK lifetime to one minute before one-shot binding.
  DELETE FROM authn WHERE ctime < UNIX_TIMESTAMP() - 60;
  INSERT IGNORE INTO authn (`token`, `value`, `ctime`) VALUES (_token, _value, UNIX_TIMESTAMP());
END$

DROP PROCEDURE IF EXISTS `socket_bind`$
CREATE PROCEDURE `socket_bind`(
  IN _args JSON
)
BEGIN
  DECLARE _socket_id varchar(32);
  DECLARE _sid varchar(64);
  DECLARE _token varchar(64) CHARACTER SET ascii;
  DECLARE _uid varchar(16) DEFAULT NULL;
  DECLARE _domain_id int unsigned DEFAULT NULL;
  DECLARE _cookie_exists int DEFAULT 0;
  DECLARE _nobody_id varchar(16) CHARACTER SET ascii;
  DECLARE _bound int DEFAULT 0;

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  SELECT JSON_VALUE(_args, '$.id') INTO _socket_id;
  SELECT JSON_VALUE(_args, '$.token') INTO _token;
  IF _socket_id IS NULL OR _socket_id = '' OR _token IS NULL OR _token = '' THEN
    SELECT 1 AS failed;
  ELSE
    START TRANSACTION;
    -- This lock is the OTAK claim. A second concurrent connection waits until
    -- the first deletes the row, then sees no credential and cannot bind.
    SELECT id INTO _sid FROM authn
      WHERE token = _token AND ctime >= UNIX_TIMESTAMP() - 60 LIMIT 1 FOR UPDATE;
    IF _sid IS NULL OR _sid = '' THEN
      -- Consume an expired matching row too: it cannot become valid later.
      DELETE FROM authn WHERE token = _token;
    ELSE
      -- Historical socket_bind consumes the OTAK exactly once after resolving
      -- the authoritative session context. Do not accept a client supplied sid.
      DELETE FROM authn WHERE token = _token;
      SELECT c.uid, e.dom_id INTO _uid, _domain_id
        FROM cookie c LEFT JOIN entity e ON e.id = c.uid
        WHERE c.id = _sid AND c.mtime + c.ttl > UNIX_TIMESTAMP()
        LIMIT 1;
      SELECT COUNT(*) INTO _cookie_exists FROM cookie
        WHERE id = _sid AND mtime + ttl > UNIX_TIMESTAMP();
      IF _cookie_exists = 0 THEN
        SELECT 1 AS failed;
      ELSE
        IF _uid IS NULL THEN
          SELECT COALESCE((SELECT conf_value FROM sys_conf WHERE conf_key = 'nobody_id' LIMIT 1), 'ffffffffffffffff')
            INTO _nobody_id;
          UPDATE cookie SET uid = _nobody_id WHERE id = _sid AND uid IS NULL;
          SELECT c.uid, e.dom_id INTO _uid, _domain_id
            FROM cookie c LEFT JOIN entity e ON e.id = c.uid
            WHERE c.id = _sid LIMIT 1;
        END IF;
        INSERT INTO socket (id, session_id, uid, domain_id, ctime, mtime)
          VALUES (_socket_id, _sid, _uid, _domain_id, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())
          ON DUPLICATE KEY UPDATE session_id = VALUES(session_id), uid = VALUES(uid),
            domain_id = VALUES(domain_id), mtime = VALUES(mtime);
        SET _bound = 1;
      END IF;
    END IF;
    COMMIT;
    IF _bound = 1 THEN
      SELECT id AS socket_id, session_id, uid, domain_id FROM socket WHERE id = _socket_id;
    ELSE
      SELECT 1 AS failed;
    END IF;
  END IF;
END$

DROP PROCEDURE IF EXISTS `socket_get`$
CREATE PROCEDURE `socket_get`(
  IN _socket_id varchar(80) CHARACTER SET ascii
)
BEGIN
  SELECT id AS socket_id, session_id, uid, domain_id, ctime, mtime
    FROM socket WHERE id = _socket_id LIMIT 1;
END$

DROP PROCEDURE IF EXISTS `socket_free`$
CREATE PROCEDURE `socket_free`(
  IN _socket_id varchar(32)
)
BEGIN
  DELETE FROM socket WHERE id = _socket_id;
END$

DROP PROCEDURE IF EXISTS `socket_list_session`$
CREATE PROCEDURE `socket_list_session`(
  IN _sid varchar(64)
)
BEGIN
  SELECT id AS socket_id, session_id, uid
    FROM socket
    WHERE session_id = _sid;
END$

DROP PROCEDURE IF EXISTS `socket_refresh`$
CREATE PROCEDURE `socket_refresh`(
  IN _endpoint varchar(256) CHARACTER SET ascii,
  IN _socket_ids JSON
)
BEGIN
  DECLARE _index int DEFAULT 0;
  DECLARE _size int DEFAULT 0;
  DECLARE _socket_id varchar(32);

  SET _size = IFNULL(JSON_LENGTH(_socket_ids), 0);
  WHILE _index < _size DO
    SELECT JSON_VALUE(_socket_ids, CONCAT('$[', _index, ']')) INTO _socket_id;
    UPDATE socket SET mtime = UNIX_TIMESTAMP() WHERE id = _socket_id;
    SET _index = _index + 1;
  END WHILE;
  DELETE FROM socket WHERE mtime < UNIX_TIMESTAMP() - 120;
END$
DELIMITER ;
