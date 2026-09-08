-- Phase 4.4 runtime-owned WebSocket/session closure. This runs after the
-- Phase 4 Yellow Page identity/session schema and intentionally contains no
-- Hub, MFS, conference or presence dependency. `authn` retains the historical
-- OTAK storage contract; its value is resolved and consumed only by socket_bind.

CREATE TABLE IF NOT EXISTS `authn` (
  `token` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `type` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.type')) VIRTUAL,
  `id` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.id')) VIRTUAL,
  `host` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`value`,'$.host')) VIRTUAL,
  `value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`value`)),
  PRIMARY KEY (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `socket` (
  `id` varchar(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `session_id` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `uid` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  `domain_id` int(11) unsigned DEFAULT NULL,
  `ctime` int(11) unsigned NOT NULL,
  `mtime` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `socket_session` (`session_id`),
  KEY `socket_uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

DELIMITER $
DROP PROCEDURE IF EXISTS `session_ensure`$
CREATE PROCEDURE `session_ensure`(
  IN _sid varchar(64) CHARACTER SET ascii
)
BEGIN
  DECLARE _session_id varchar(64) CHARACTER SET ascii;

  IF _sid IS NOT NULL AND _sid REGEXP '^[A-Za-z0-9_-]{16,64}$' THEN
    SELECT id INTO _session_id FROM cookie WHERE id = _sid LIMIT 1;
  END IF;
  IF _session_id IS NULL THEN
    SET _session_id = CONCAT(uniqueId(), uniqueId());
    INSERT INTO cookie (id, uid, ctime, mtime, ua, ttl, failed, status)
      VALUES (_session_id, NULL, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 'runtime', 2592000, 0, 'new');
  END IF;
  SELECT id AS session_id, uid, status FROM cookie WHERE id = _session_id LIMIT 1;
END$

DROP PROCEDURE IF EXISTS `authn_store`$
CREATE PROCEDURE `authn_store`(
  IN _token VARCHAR(90) CHARACTER SET ascii,
  IN _value JSON
)
BEGIN
  INSERT IGNORE INTO authn (`token`, `value`) VALUES (_token, _value);
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

  SELECT JSON_VALUE(_args, '$.id') INTO _socket_id;
  SELECT JSON_VALUE(_args, '$.token') INTO _token;
  IF _socket_id IS NULL OR _socket_id = '' OR _token IS NULL OR _token = '' THEN
    SELECT 1 AS failed;
  ELSE
    SELECT id INTO _sid FROM authn WHERE token = _token LIMIT 1;
    IF _sid IS NULL OR _sid = '' THEN
      SELECT 1 AS failed;
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
        INSERT INTO socket (id, session_id, uid, domain_id, ctime, mtime)
          VALUES (_socket_id, _sid, _uid, _domain_id, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())
          ON DUPLICATE KEY UPDATE session_id = VALUES(session_id), uid = VALUES(uid),
            domain_id = VALUES(domain_id), mtime = VALUES(mtime);
        SELECT id AS socket_id, session_id, uid, domain_id FROM socket WHERE id = _socket_id;
      END IF;
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
