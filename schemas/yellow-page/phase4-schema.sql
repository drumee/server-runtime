-- Minimal Phase 4 Yellow Page closure. It intentionally contains only the
-- source-derived identity, provisioned system-principal configuration, cookie,
-- Domain privilege and procedure objects required by session_signin() and
-- domain_permission(). System Drumates are provisioned by organisation setup;
-- this runtime closure resolves them but never creates them.

CREATE TABLE IF NOT EXISTS `domain` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`) USING HASH
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `sys_conf` (
  `conf_key` varchar(40) NOT NULL,
  `conf_value` longtext DEFAULT NULL,
  PRIMARY KEY (`conf_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE IF NOT EXISTS `entity` (
  `id` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `ident` varchar(80) DEFAULT NULL,
  `vhost` varchar(512) DEFAULT NULL,
  `db_name` varchar(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `db_host` varchar(255) NOT NULL DEFAULT '',
  `fs_host` varchar(255) NOT NULL DEFAULT '',
  `home_dir` varchar(512) NOT NULL DEFAULT '',
  `home_id` varchar(16) DEFAULT NULL,
  `type` enum('organization','hub','drumate','shop','blog','forum','guest','dummy') DEFAULT NULL,
  `dom_id` int(11) unsigned DEFAULT NULL,
  `area` enum('public','share','limited','restricted','private','personal','system','dummy','dmz-public','dmz-private','dmz','pool','pool/dmz','template') DEFAULT NULL,
  `area_id` varbinary(16) DEFAULT NULL,
  `status` enum('active','frozen','deleted','archived','system','locked','online','offline','hidden') DEFAULT NULL,
  `ctime` int(11) unsigned NOT NULL,
  `mtime` int(11) unsigned NOT NULL,
  `settings` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `db_name` (`db_name`),
  UNIQUE KEY `home_dir` (`home_dir`),
  UNIQUE KEY `home_id` (`home_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE IF NOT EXISTS `drumate` (
  `sys_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `id` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  `username` varchar(80) DEFAULT NULL,
  `domain_id` int(11) unsigned DEFAULT NULL,
  `fingerprint` varchar(128) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL DEFAULT '',
  `profile` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`profile`)),
  `firstname` varchar(128) GENERATED ALWAYS AS (json_value(`profile`,'$.firstname')) VIRTUAL,
  `lastname` varchar(128) GENERATED ALWAYS AS (json_value(`profile`,'$.lastname')) VIRTUAL,
  `fullname` varchar(128) GENERATED ALWAYS AS (if(concat(ifnull(`firstname`,''),' ',ifnull(`lastname`,'')) = ' ',json_value(`profile`,'$.email'),concat(ifnull(`firstname`,''),' ',ifnull(`lastname`,'')))) VIRTUAL,
  `email` varchar(128) CHARACTER SET ascii COLLATE ascii_general_ci GENERATED ALWAYS AS (json_value(`profile`,'$.email')) VIRTUAL,
  `dmail` varchar(128) GENERATED ALWAYS AS (json_value(`profile`,'$.dmail')) VIRTUAL,
  PRIMARY KEY (`sys_id`),
  UNIQUE KEY `id` (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `_ident` (`username`,`domain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `cookie` (
  `id` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `uid` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `ctime` int(11) NOT NULL DEFAULT 0,
  `mtime` int(11) NOT NULL DEFAULT 0,
  `ua` mediumtext NOT NULL DEFAULT '',
  `ttl` int(11) NOT NULL DEFAULT 86400,
  `failed` tinyint(4) unsigned DEFAULT 0,
  `status` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE IF NOT EXISTS `privilege` (
  `sys_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `uid` varchar(16) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  `domain_id` int(11) unsigned NOT NULL,
  `privilege` int(4) unsigned DEFAULT 0,
  `is_authoritative` tinyint(4) DEFAULT 0,
  PRIMARY KEY (`sys_id`),
  UNIQUE KEY `uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

DELIMITER $
DROP FUNCTION IF EXISTS `uniqueId`$
CREATE FUNCTION `uniqueId`()
RETURNS VARCHAR(16) DETERMINISTIC
BEGIN
  DECLARE _res VARCHAR(16);
  SELECT CONCAT(SUBSTRING_INDEX(UUID(), '-', 1),SUBSTRING_INDEX(UUID(), '-', 1)) INTO _res;
  RETURN _res;
END$

DROP FUNCTION IF EXISTS `domain_permission`$
CREATE FUNCTION `domain_permission`(
  _uid VARCHAR(80),
  _dom_id INT,
  _perm TINYINT(6)
)
RETURNS TINYINT(6) DETERMINISTIC
BEGIN
  DECLARE _res TINYINT(6);
  SELECT privilege&_perm FROM privilege
    WHERE `uid` = _uid AND domain_id=_dom_id INTO _res;
  RETURN IFNULL(_res, 0);
END$
DELIMITER ;

DELIMITER $
DROP PROCEDURE IF EXISTS `session_signin`$
CREATE PROCEDURE `session_signin`(
  IN _args JSON
)
BEGIN
  DECLARE _username VARCHAR(128);
  DECLARE _host VARCHAR(128);
  DECLARE _pw VARCHAR(128);
  DECLARE _cid VARCHAR(64);
  DECLARE _otp VARCHAR(64) DEFAULT "0";
  DECLARE _domain_name VARCHAR(1000);
  DECLARE _uid VARCHAR(128) DEFAULT NULL;
  DECLARE _profile JSON DEFAULT "{}";
  DECLARE _sid VARCHAR(64);
  DECLARE _db_name VARCHAR(52) DEFAULT '0';
  DECLARE _ctime INT(11);
  DECLARE _email VARCHAR(500);
  DECLARE _dom_id INT(8) DEFAULT 1;
  DECLARE _ident VARCHAR(128) DEFAULT NULL;
  DECLARE _nobody_id VARCHAR(16) CHARACTER SET ascii;

  SELECT JSON_VALUE(_args, "$.uid") INTO _ident;
  SELECT JSON_VALUE(_args, "$.password") INTO _pw;
  SELECT JSON_VALUE(_args, "$.sid") INTO _cid;
  SELECT JSON_VALUE(_args, "$.username") INTO _username;
  SELECT JSON_VALUE(_args, "$.host") INTO _host;
  -- Organisation provisioning records the default anonymous Drumate in
  -- sys_conf. The canonical constant is a compatibility fallback only; the
  -- runtime never provisions or synthesizes that principal.
  SELECT COALESCE((SELECT conf_value FROM sys_conf WHERE conf_key='nobody_id' LIMIT 1), 'ffffffffffffffff')
    INTO _nobody_id;

  IF (_username IS NOT NULL) AND (_host IS NOT NULL) AND (_ident IS NULL) THEN
    SELECT d.id FROM drumate d INNER JOIN domain o ON o.id=d.domain_id
      WHERE username=_username AND name=_host INTO _ident;
  END IF;

  SELECT e.id, `profile`, db_name, d.email, o.name, o.id FROM drumate d
    INNER JOIN entity e ON e.id=d.id
    INNER JOIN domain o ON o.id=e.dom_id
    WHERE fingerprint=sha2(_pw, 512) AND (e.id=_ident OR email=_ident)
      INTO _uid, _profile, _db_name, _email, _domain_name, _dom_id;

  SELECT id FROM cookie WHERE id=_cid INTO _sid;

  IF _sid IS NULL THEN
    SELECT IF(_cid IS NULL OR _cid="", concat(uniqueId(), uniqueId()), _cid) INTO _sid;
    SELECT _sid INTO _cid;
    SELECT UNIX_TIMESTAMP() INTO _ctime;
    INSERT INTO cookie (`id`,`uid`,`ctime`,`mtime`,`ua`, `status`)
      VALUES(_sid, _nobody_id, _ctime, _ctime, 'no_cookie', 'new');
  END IF;

  IF _uid IS NULL THEN
    UPDATE cookie SET failed=failed+1, `status`='wrong_credentials' WHERE id=_cid;
    SELECT id session_id, failed, `status` FROM cookie WHERE id=_cid;
  ELSE
    SELECT IFNULL(JSON_VALUE(_profile, "$.otp"), "") INTO _otp;
    UPDATE cookie SET
      failed=0,
      mtime=UNIX_TIMESTAMP(),
      `uid` = _uid,
      status = IF(_otp IN ("0", ""), 'ok', 'otp'),
      ttl = IFNULL(JSON_VALUE(_profile, "$.session_ttl"), 2592000)
    WHERE id=_cid;
    SELECT
      c.id AS session_id,
      e.id,
      e.id AS hub_id,
      d.username AS ident,
      d.username,
      d.fullname,
      _domain_name AS domain,
      _dom_id AS domain_id,
      db_name,
      db_host,
      fs_host,
      vhost,
      home_dir,
      home_id,
      c.status,
      email,
      dmail,
      firstname,
      lastname,
      NULL mimicker,
      area,
      area_id as aid,
      e.status AS `condition`,
      e.mtime,
      e.ctime,
      _profile AS `profile`,
      IFNULL(JSON_VALUE(_profile, '$.onboarded'), FALSE) AS onboarded
    FROM entity e INNER JOIN (drumate d, cookie c) ON e.id=d.id AND e.id=c.uid
      WHERE d.id=_uid AND c.id=_cid;
  END IF;
END$
DELIMITER ;
