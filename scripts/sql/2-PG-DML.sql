INSERT INTO relying_parties (external_id, name, origin, icon_url, description)
VALUES ('example.com', 'Example Service', 'https://example.com', 'https://example.com/icon.png', 'RP for example.com web traffic')
RETURNING id;


-- 1. Challenge Expiration Time or timeout
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (1, 'timeout', '300');

-- 2. user_verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (1, 'require_user_verification', 'true');

-- 3. authenticator attachment
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (1, 'authenticator_attachment', 'platform');


-- 4. Require User Verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (1, 'require_resident_key', 'true');

INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (1, 'public_key_alg', '-7,-257,-37,-8,-35,-36');


--- netlify app
INSERT INTO relying_parties (external_id, name, origin, icon_url, description)
VALUES ('pp-signal-sdk-demo.netlify.app', 'PP Signal netlify app', 'https://pp-signal-sdk-demo.netlify.app', 'https://example.com/icon.png', 'RP for example.com web traffic')
RETURNING id;

-- 1. Challenge Expiration Time or timeout
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'timeout', '300');

-- 2. user_verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'require_user_verification', 'true');

-- 3. authenticator attachment
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'authenticator_attachment', 'platform');


-- 4. Require User Verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'require_resident_key', 'true');

INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'public_key_alg', '-7,-257,-37,-8,-35,-36');


-- Sample user
insert into users (id, external_id, username, email, display_name, created_at, updated_at)
values (0, '65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk', 'testuser4', 'testuser4@netlify.app', 'TestUser4', NOW(), NOW());


INSERT INTO relying_parties (external_id, name, origin, icon_url, description)
VALUES ('effortless-yeot-a266e9.netlify.app', 'Saas App', 'https://effortless-yeot-a266e9.netlify.app/', 'https://example.com/icon.png', 'RP for SaaS app web traffic')
RETURNING id;

-- 1. Challenge Expiration Time or timeout
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'timeout', '300');

-- 2. user_verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'require_user_verification', 'true');

-- 3. authenticator attachment
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'authenticator_attachment', 'platform');


-- 4. Require User Verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'require_resident_key', 'true');

INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (2, 'public_key_alg', '-7,-257,-37,-8,-35,-36');

-- Sample user
insert into users (id, external_id, username, email, display_name, created_at, updated_at)
values (0, '65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk', 'testuser4', 'testuser4@netlify.app', 'TestUser4', NOW(), NOW());




INSERT INTO relying_parties (external_id, name, origin, icon_url, description)
VALUES ('https://www.sowmya.com', 'sowmya_local_rp', 'https://www.sowmya.com', 'https://example.com/icon.png', 'RP for local testing')
RETURNING id;

select * from relying_parties;

-- 1. Challenge Expiration Time or timeout
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (4, 'timeout', '300');

-- 2. user_verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (4, 'require_user_verification', 'true');

-- 3. authenticator attachment
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (4, 'authenticator_attachment', 'platform');


-- 4. Require User Verification
INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (4, 'require_resident_key', 'true');

INSERT INTO relying_party_configs (rp_id, setting_key, setting_value)
VALUES (4, 'public_key_alg', '-7,-257,-37,-8,-35,-36');













