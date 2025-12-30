-- ============================================================================
-- Stored Procedure: populate_sample_data()
-- Description: Populates sample relying parties, configurations, and users
-- ============================================================================

-- Temp table only lives for the session
CREATE TEMP TABLE tmp_rp (
  external_id VARCHAR,
  name VARCHAR,
  origin VARCHAR,
  icon_url VARCHAR,
  description TEXT,
  timeout VARCHAR,
  require_user_verification VARCHAR,
  authenticator_attachment VARCHAR,
  require_resident_key VARCHAR,
  public_key_alg VARCHAR
);

INSERT INTO tmp_rp (
    external_id,
    name,
    origin,
    icon_url,
    description,
    timeout,
    require_user_verification,
    authenticator_attachment,
    require_resident_key,
    public_key_alg
) VALUES
      ('example.com','Example Service','https://example.com','https://example.com/icon.png','RP for example.com web traffic','300','true','platform','true','-7,-257,-37,-8,-35,-36'),
      ('example2.com','Example2 Service','https://example2.com','https://example2.com/icon.png','RP2 for example.com web traffic','300','true','platform','true','-7,-257,-37,-8,-35,-36');

DO $$
DECLARE
  -- Sample User Values (Optional, can be removed if not needed)
v_user_external_id VARCHAR := '65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk';
  v_user_username VARCHAR := 'testuser4';
  v_user_email VARCHAR := 'testuser4@netlify.app';
  v_user_display_name VARCHAR := 'TestUser4';

  -- Variables to store inserted IDs
  v_rp_id BIGINT;
  v_rp_record RECORD;
BEGIN
  -- ========================================
  -- Insert Sample User
  -- ========================================
INSERT INTO USERS (id, external_id, username, email, display_name, created_at, updated_at)
VALUES (0, v_user_external_id, v_user_username, v_user_email, v_user_display_name, NOW(), NOW());

-- ========================================
-- Loop through relying parties temp table
-- ========================================
FOR v_rp_record IN SELECT * FROM tmp_rp LOOP
                                 -- Insert Relying Party
    INSERT INTO RELYING_PARTIES (external_id, name, origin, icon_url, description)
                   VALUES (
                       v_rp_record.external_id,
                       v_rp_record.name,
                       v_rp_record.origin,
                       v_rp_record.icon_url,
                       v_rp_record.description
                       )
                       RETURNING id INTO v_rp_id;

-- Insert Configuration Settings for this RP
INSERT INTO RELYING_PARTY_CONFIGS (rp_id, setting_key, setting_value)
VALUES
    (v_rp_id, 'timeout', v_rp_record.timeout),
    (v_rp_id, 'require_user_verification', v_rp_record.require_user_verification),
    (v_rp_id, 'authenticator_attachment', v_rp_record.authenticator_attachment),
    (v_rp_id, 'require_resident_key', v_rp_record.require_resident_key),
    (v_rp_id, 'public_key_alg', v_rp_record.public_key_alg);
END LOOP;

  -- ========================================
  -- Print Summary
  -- ========================================
  RAISE NOTICE '====================================';
  RAISE NOTICE 'Sample data populated successfully!';
  RAISE NOTICE 'Total RPs inserted: %', (SELECT COUNT(*) FROM tmp_rp);
  RAISE NOTICE '====================================';
END $$;
