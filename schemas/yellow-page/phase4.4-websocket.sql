-- Phase 4.4 runtime-owned WebSocket/session closure. This runs after the
-- Phase 4 Yellow Page identity/session schema and intentionally contains no
-- Hub, MFS, conference, presence or historical authn dependencies.

CREATE TABLE IF NOT EXISTS `socket` (
  `id` varchar(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `session_id` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `uid` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `domain_id` int(11) unsigned NOT NULL,
  `ctime` int(11) unsigned NOT NULL,
  `mtime` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `socket_session` (`session_id`),
  KEY `socket_uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

DELIMITER $
DROP PROCEDURE IF EXISTS `socket_bind`$
CREATE PROCEDURE `socket_bind`(
  IN _args JSON
)
BEGIN
  DECLARE _socket_id varchar(32);
  DECLARE _sid varchar(64);
  DECLARE _uid varchar(16) DEFAULT NULL;
  DECLARE _domain_id int unsigned DEFAULT NULL;

  SELECT JSON_VALUE(_args, '$.id') INTO _socket_id;
  SELECT JSON_VALUE(_args, '$.sid') INTO _sid;
  IF _socket_id IS NULL OR _socket_id = '' OR _sid IS NULL OR _sid = '' THEN
    SELECT 1 AS failed;
  ELSE
    SELECT c.uid, e.dom_id INTO _uid, _domain_id
      FROM cookie c INNER JOIN entity e ON e.id = c.uid
      WHERE c.id = _sid AND c.status = 'ok' AND c.mtime + c.ttl > UNIX_TIMESTAMP()
      LIMIT 1;
    IF _uid IS NULL OR _domain_id IS NULL THEN
      SELECT 1 AS failed;
    ELSE
      INSERT INTO socket (id, session_id, uid, domain_id, ctime, mtime)
        VALUES (_socket_id, _sid, _uid, _domain_id, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())
        ON DUPLICATE KEY UPDATE session_id = VALUES(session_id), uid = VALUES(uid),
          domain_id = VALUES(domain_id), mtime = VALUES(mtime);
      SELECT id AS socket_id, session_id, uid, domain_id FROM socket WHERE id = _socket_id;
    END IF;
  END IF;
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
