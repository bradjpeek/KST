-- Generated by Oracle SQL Developer Data Modeler 18.1.0.082.1035
--   at:        2018-05-06 23:17:33 CDT
--   site:      Oracle Database 11g
--   type:      Oracle Database 11g



CREATE TABLE facility (
    facility_id     NUMBER(10) NOT NULL,
    facility_name   VARCHAR2(255) NOT NULL,
    address_1       VARCHAR2(60),
    address_2       VARCHAR2(60),
    city            VARCHAR2(45) NOT NULL,
    state           VARCHAR2(2) NOT NULL,
    postal_code     VARCHAR2(9),
    email_address   VARCHAR2(100),
    latitude        NUMBER,
    longitude       NUMBER,
    contact_name    VARCHAR2(60),
    contact_phone   VARCHAR2(25),
    when_created    DATE NOT NULL,
    created_by      VARCHAR2(100) NOT NULL,
    when_updated    DATE NOT NULL,
    updated_by      VARCHAR2(100) NOT NULL
);

ALTER TABLE facility ADD CONSTRAINT facility_pk PRIMARY KEY ( facility_id );

CREATE TABLE kst_app_user (
    email_address                VARCHAR2(100) NOT NULL,
    password_hash                VARCHAR2(64) NOT NULL,
    first_name                   VARCHAR2(60) NOT NULL,
    last_name                    VARCHAR2(60) NOT NULL,
    is_member                    VARCHAR2(1) NOT NULL,
    is_admin                     VARCHAR2(1) NOT NULL,
    member_since                 DATE,
    member_expire_date           DATE NOT NULL,
    search_allowed               VARCHAR2(1) NOT NULL,
    autopay_allowed              VARCHAR2(1) NOT NULL,
    stripe_customer_id           VARCHAR2(45),
    credit_balance               NUMBER(5,2),
    member_discount_pct          NUMBER(3,2),
    chat_username                VARCHAR2(25),
    password_reset_code          NUMBER(6),
    last_pw_reset_request_dttm   DATE,
    last_pw_change_dttm          DATE,
    when_created                 DATE NOT NULL,
    created_by                   VARCHAR2(100) NOT NULL,
    when_updated                 DATE NOT NULL,
    updated_by                   VARCHAR2(100) NOT NULL
)
LOGGING;

ALTER TABLE kst_app_user
    ADD CHECK ( is_member IN (
        'N',
        'Y'
    ) );

ALTER TABLE kst_app_user
    ADD CHECK ( is_admin IN (
        'N',
        'Y'
    ) );

ALTER TABLE kst_app_user
    ADD CHECK ( search_allowed IN (
        'N',
        'Y'
    ) );

ALTER TABLE kst_app_user
    ADD CHECK ( autopay_allowed IN (
        'N',
        'Y'
    ) );

COMMENT ON COLUMN kst_app_user.password_hash IS
    'SHA256 Hash of user specified password.';

COMMENT ON COLUMN kst_app_user.member_expire_date IS
    'Membership expires on this date';

COMMENT ON COLUMN kst_app_user.search_allowed IS
    'Y = search of player contact info by other members is allowed';

COMMENT ON COLUMN kst_app_user.stripe_customer_id IS
    'Customer ID assigned by Stripe for payment';

COMMENT ON COLUMN kst_app_user.member_discount_pct IS
    'Optional discount percentage appllied to invoices.  50% stored as .5.   100% discount stored as 1.0';

COMMENT ON COLUMN kst_app_user.chat_username IS
    'Username to display in comments and or chats';

COMMENT ON COLUMN kst_app_user.password_reset_code IS
    'Numeric code use to authenticate a password reset request.';

COMMENT ON COLUMN kst_app_user.last_pw_reset_request_dttm IS
    'Date and time of most recent password reset request.';

COMMENT ON COLUMN kst_app_user.last_pw_change_dttm IS
    'Date and time of last password change.';

ALTER TABLE kst_app_user ADD CONSTRAINT kst_app_user_pk PRIMARY KEY ( email_address );

CREATE TABLE kst_invoice (
    kst_invoice_id          NUMBER(10) NOT NULL,
    invoice_status          VARCHAR2(15) NOT NULL,
    issue_date              DATE NOT NULL,
    invoice_amount          NUMBER(5,2) NOT NULL,
    credit_amount_applied   NUMBER(5,2),
    balance_due             NUMBER(6,2) NOT NULL,
    paid_amount             NUMBER(5,2),
    paid_date               DATE,
    was_autopay             VARCHAR2(1) NOT NULL,
    stripe_payment_id       VARCHAR2(25),
    notes                   VARCHAR2(1000),
    when_created            DATE NOT NULL,
    when_updated            DATE
)
LOGGING;

ALTER TABLE kst_invoice
    ADD CHECK ( was_autopay IN (
        'N',
        'Y'
    ) );

COMMENT ON COLUMN kst_invoice.invoice_status IS
    'PENDING::PAID IN FULL::PARTIALLY PAID::WAIVED';

COMMENT ON COLUMN kst_invoice.credit_amount_applied IS
    'Option credit amount that was applied to the invoice.   The invoice amount is after any credits were applied.';

COMMENT ON COLUMN kst_invoice.balance_due IS
    'Balance due reflects previous balance plus current invoice amount minus credits applied.';

COMMENT ON COLUMN kst_invoice.stripe_payment_id IS
    'Payment id from Stripe (if stripe was used)';

ALTER TABLE kst_invoice ADD CONSTRAINT kst_invoice_pk PRIMARY KEY ( kst_invoice_id );

CREATE TABLE kst_member_comment (
    kst_member_comment_id        NUMBER(10) NOT NULL,
    kst_app_user_email_address   VARCHAR2(100) NOT NULL,
    comment_dttm                 DATE NOT NULL,
    comment_section              NUMBER(10) NOT NULL,
    comment_subject              VARCHAR2(60),
    mbr_comment                  VARCHAR2(2000) NOT NULL,
    reply_to_comment_id          NUMBER(10),
    when_created                 DATE NOT NULL,
    when_updated                 DATE
)
LOGGING;

COMMENT ON COLUMN kst_member_comment.comment_section IS
    'Application section where this comment was created';

COMMENT ON COLUMN kst_member_comment.comment_subject IS
    'Optional subject for the comment';

ALTER TABLE kst_member_comment ADD CONSTRAINT kst_member_comment_pk PRIMARY KEY ( kst_member_comment_id );

CREATE TABLE ladder_position (
    ladder_position_id   NUMBER(10) NOT NULL,
    player_id            NUMBER(10) NOT NULL,
    league_id            NUMBER(10) NOT NULL,
    as_of_date           DATE NOT NULL,
    ladder_position      NUMBER(2) NOT NULL,
    prev_position        NUMBER(2) NOT NULL,
    starting_position    NUMBER(2) NOT NULL,
    when_created         DATE NOT NULL,
    created_by           VARCHAR2(100) NOT NULL,
    when_updated         DATE NOT NULL,
    updated_by           VARCHAR2(100) NOT NULL
);

ALTER TABLE ladder_position ADD CONSTRAINT ladder_position_pk PRIMARY KEY ( ladder_position_id );

CREATE TABLE league (
    league_id         NUMBER(10) NOT NULL,
    league_name       VARCHAR2(100) NOT NULL,
    league_city       VARCHAR2(45) NOT NULL,
    league_state      VARCHAR2(2) NOT NULL,
    start_date        DATE NOT NULL,
    end_date          DATE NOT NULL,
    contact_name      VARCHAR2(100) NOT NULL,
    contact_email     VARCHAR2(100) NOT NULL,
    contact_phone     VARCHAR2(25),
    match_format_id   NUMBER(10),
    facility_id       NUMBER(10),
    when_created      DATE NOT NULL,
    created_by        VARCHAR2(100) NOT NULL,
    when_updated      DATE NOT NULL,
    updated_by        VARCHAR2(100) NOT NULL
);

COMMENT ON COLUMN league.facility_id IS
    'Optional ID of primary facility for the league';

ALTER TABLE league ADD CONSTRAINT league_pk PRIMARY KEY ( league_id );

ALTER TABLE league ADD CONSTRAINT league_ak1 UNIQUE ( league_name );

CREATE TABLE match_format (
    match_format_id      NUMBER(10) NOT NULL,
    match_format         VARCHAR2(20) NOT NULL,
    match_format_descr   VARCHAR2(255) NOT NULL,
    match_format_notes   VARCHAR2(2000),
    gender               VARCHAR2(10) NOT NULL,
    is_ladder            VARCHAR2(1) NOT NULL,
    when_created         DATE NOT NULL,
    created_by           VARCHAR2(100) NOT NULL,
    when_updated         DATE NOT NULL,
    updated_by           VARCHAR2(100) NOT NULL
);

ALTER TABLE match_format
    ADD CONSTRAINT ck_match_format_is_ladder CHECK ( is_ladder IN (
        'N',
        'Y'
    ) );

ALTER TABLE match_format ADD CONSTRAINT match_format_pk PRIMARY KEY ( match_format_id );

CREATE TABLE match_score (
    match_score_id            NUMBER(10) NOT NULL,
    match_status              VARCHAR2(10) NOT NULL,
    match_format_id           NUMBER(10) NOT NULL,
    scheduled_date            DATE NOT NULL,
    completed_date            DATE,
    league_id                 NUMBER(10),
    facility_id               NUMBER(10),
    home_player_id            NUMBER(10) NOT NULL,
    visitor_player_id         NUMBER(10) NOT NULL,
    home_player2_id           NUMBER(10),
    visitor_player2_id        NUMBER(10),
    home_games_won_set_1      NUMBER(2),
    visitor_games_won_set_1   NUMBER(2),
    home_games_won_set_2      NUMBER(2),
    visitor_games_won_set_2   NUMBER(2),
    home_games_won_set_3      NUMBER(2),
    visitor_games_won_set_3   NUMBER(2),
    home_games_won_set_4      NUMBER(2),
    visitor_games_won_set_4   NUMBER(2),
    home_games_won_set_5      NUMBER(2),
    visitor_games_won_set_5   NUMBER(2),
    result_was_disputed       VARCHAR2(1) DEFAULT 'N' NOT NULL,
    dispute_resolved          VARCHAR2(1),
    notes                     VARCHAR2(1000),
    when_created              DATE NOT NULL,
    created_by                VARCHAR2(100) NOT NULL,
    when_updated              DATE NOT NULL,
    updated_by                VARCHAR2(100) NOT NULL
);

ALTER TABLE match_score
    ADD CONSTRAINT match_score_ck01 CHECK ( match_status IN (
        'COMPLETED',
        'DISPUTED',
        'SCHEDULED'
    ) );

ALTER TABLE match_score
    ADD CHECK ( result_was_disputed IN (
        'N',
        'Y'
    ) );

ALTER TABLE match_score
    ADD CHECK ( dispute_resolved IN (
        'N',
        'Y'
    ) );

COMMENT ON COLUMN match_score.match_status IS
    'SCHEDULED::COMPLETED::DISPUTED::RESCHEDULED::CANCELLED';

COMMENT ON COLUMN match_score.home_player2_id IS
    'optional ID for 2nd player on home doubles team';

COMMENT ON COLUMN match_score.visitor_player2_id IS
    'optional ID for 2nd player on visitor doubles team';

ALTER TABLE match_score ADD CONSTRAINT match_score_pk PRIMARY KEY ( match_score_id );

CREATE TABLE player (
    player_id       NUMBER(10) NOT NULL,
    email_address   VARCHAR2(100) NOT NULL,
    player_name     VARCHAR2(100) NOT NULL,
    gender          VARCHAR2(1) NOT NULL,
    address_1       VARCHAR2(60),
    address_2       VARCHAR2(60),
    city            VARCHAR2(45),
    state           VARCHAR2(2),
    postal_code     VARCHAR2(9),
    phone           VARCHAR2(25),
    rating          NUMBER(2,1),
    latitude        NUMBER,
    longitude       NUMBER,
    when_created    DATE NOT NULL,
    created_by      VARCHAR2(100) NOT NULL,
    when_updated    DATE NOT NULL,
    updated_by      VARCHAR2(100) NOT NULL
);

ALTER TABLE player ADD CONSTRAINT player_pk PRIMARY KEY ( player_id );

ALTER TABLE player ADD CONSTRAINT player_ak1 UNIQUE ( email_address );

CREATE TABLE player_facility_assoc (
    player_facility_assoc_id   NUMBER(10) NOT NULL,
    player_player_id           NUMBER(10) NOT NULL,
    facility_facility_id       NUMBER(10) NOT NULL,
    when_created               DATE NOT NULL,
    created_by                 VARCHAR2(100) NOT NULL,
    when_updated               DATE NOT NULL,
    updated_by                 VARCHAR2(100) NOT NULL
);

ALTER TABLE player_facility_assoc ADD CONSTRAINT player_facility_assoc_pk PRIMARY KEY ( player_facility_assoc_id );

CREATE TABLE team (
    team_id                NUMBER(10) NOT NULL,
    team_number            NUMBER NOT NULL,
    team_name              VARCHAR2(80) NOT NULL,
    team_captain           VARCHAR2(100) NOT NULL,
    team_captain_phone     VARCHAR2(30) NOT NULL,
    team_captain_email     VARCHAR2(100) NOT NULL,
    facility_facility_id   NUMBER(10),
    when_created           DATE NOT NULL,
    created_by             VARCHAR2(100) NOT NULL,
    when_updated           DATE NOT NULL,
    updated_by             VARCHAR2(100) NOT NULL
);

COMMENT ON COLUMN team.facility_facility_id IS
    'Optional facility associated with this team.';

ALTER TABLE team ADD CONSTRAINT team_pk PRIMARY KEY ( team_id );

ALTER TABLE team ADD CONSTRAINT team_ak1 UNIQUE ( team_number );

CREATE TABLE team_league_assoc (
    team_league_assoc_id   NUMBER(10) NOT NULL,
    league_id              NUMBER(10) NOT NULL,
    team_id                NUMBER(10) NOT NULL,
    player_id              NUMBER(10) NOT NULL,
    when_created           DATE NOT NULL,
    created_by             VARCHAR2(100) NOT NULL,
    when_updated           DATE NOT NULL,
    updated_by             VARCHAR2(100) NOT NULL
);

ALTER TABLE team_league_assoc ADD CONSTRAINT team_league_assoc_pk PRIMARY KEY ( team_league_assoc_id );

ALTER TABLE kst_member_comment
    ADD CONSTRAINT kst_member_comment_fk1 FOREIGN KEY ( reply_to_comment_id )
        REFERENCES kst_member_comment ( kst_member_comment_id )
    NOT DEFERRABLE;

ALTER TABLE kst_member_comment
    ADD CONSTRAINT kst_member_comment_fk2 FOREIGN KEY ( kst_app_user_email_address )
        REFERENCES kst_app_user ( email_address )
    NOT DEFERRABLE;

ALTER TABLE ladder_position
    ADD CONSTRAINT ladder_position_fk1 FOREIGN KEY ( league_id )
        REFERENCES league ( league_id )
    NOT DEFERRABLE;

ALTER TABLE ladder_position
    ADD CONSTRAINT ladder_position_fk2 FOREIGN KEY ( player_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE league
    ADD CONSTRAINT league_fk1 FOREIGN KEY ( facility_id )
        REFERENCES facility ( facility_id )
    NOT DEFERRABLE;

ALTER TABLE league
    ADD CONSTRAINT league_fk2 FOREIGN KEY ( match_format_id )
        REFERENCES match_format ( match_format_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk1 FOREIGN KEY ( facility_id )
        REFERENCES facility ( facility_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk2 FOREIGN KEY ( home_player_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk3 FOREIGN KEY ( home_player2_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk4 FOREIGN KEY ( league_id )
        REFERENCES league ( league_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk5 FOREIGN KEY ( match_format_id )
        REFERENCES match_format ( match_format_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk6 FOREIGN KEY ( visitor_player_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE match_score
    ADD CONSTRAINT match_score_fk7 FOREIGN KEY ( visitor_player2_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE player_facility_assoc
    ADD CONSTRAINT player_facility_assoc_fk1 FOREIGN KEY ( player_player_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE player_facility_assoc
    ADD CONSTRAINT player_facility_assoc_fk2 FOREIGN KEY ( facility_facility_id )
        REFERENCES facility ( facility_id )
    NOT DEFERRABLE;

ALTER TABLE team
    ADD CONSTRAINT team_fk1 FOREIGN KEY ( facility_facility_id )
        REFERENCES facility ( facility_id )
    NOT DEFERRABLE;

ALTER TABLE team_league_assoc
    ADD CONSTRAINT team_league_assoc_fk1 FOREIGN KEY ( league_id )
        REFERENCES league ( league_id )
    NOT DEFERRABLE;

ALTER TABLE team_league_assoc
    ADD CONSTRAINT team_league_assoc_fk2 FOREIGN KEY ( player_id )
        REFERENCES player ( player_id )
    NOT DEFERRABLE;

ALTER TABLE team_league_assoc
    ADD CONSTRAINT team_league_assoc_fk3 FOREIGN KEY ( team_id )
        REFERENCES team ( team_id )
    NOT DEFERRABLE;

CREATE OR REPLACE TRIGGER facility_biu_trg 
    BEFORE INSERT OR UPDATE ON facility 
    FOR EACH ROW 
BEGIN 
	if :new.facility_id is null then
	   :new.facility_id := kst_main_seq.nextval;
	end if;
	
	if inserting then
	    :new.when_created := sysdate;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	end if;
	
	:new.when_updated := sysdate;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER KST_APP_USER_BIU_TRG 
    BEFORE INSERT OR UPDATE ON KST_APP_USER 
    FOR EACH ROW 
BEGIN
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER KST_INVOICE_BIU_TRG 
    BEFORE INSERT OR UPDATE ON KST_INVOICE 
    FOR EACH ROW 
BEGIN
   IF
      :new.kst_invoice_id IS NULL
   THEN
      :new.kst_invoice_id := kst_invoice_seq.nextval;
   END IF;

   IF
     inserting
   THEN
     :new.when_created := SYSDATE;
   END IF;

   :new.when_updated := SYSDATE;
END ; 
/

CREATE OR REPLACE TRIGGER KST_MEMBER_COMMENT_BIU_TRG 
    BEFORE INSERT OR UPDATE ON KST_MEMBER_COMMENT 
    FOR EACH ROW 
BEGIN
   IF
     :new.kst_member_comment_id IS NULL
   THEN
     :new.kst_member_comment_id := kst_main_seq.nextval;
   END IF;

   IF
     inserting
   THEN
     :new.when_created := SYSDATE;
   END IF;

   :new.when_updated := SYSDATE;

END ; 
/

CREATE OR REPLACE TRIGGER LADDER_POSITION_BIU_TRG 
    BEFORE INSERT OR UPDATE ON ladder_position 
    FOR EACH ROW 
BEGIN
     IF
	    :new.ladder_position_id IS NULL
	THEN
	    :new.ladder_position_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER LEAGUE_BIU_TRG 
    BEFORE INSERT OR UPDATE ON league 
    FOR EACH ROW 
BEGIN
	IF
	    :new.league_id IS NULL
	THEN
	    :new.league_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER MATCH_FORMAT_BIU_TRG 
    BEFORE INSERT OR UPDATE ON match_format 
    FOR EACH ROW 
BEGIN
     IF
	    :new.match_format_id IS NULL
	THEN
	    :new.match_format_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER MATCH_SCORE_BIU_TRG 
    BEFORE INSERT OR UPDATE ON match_score 
    FOR EACH ROW 
BEGIN
	IF
	    :new.match_score_id IS NULL
	THEN
	    :new.match_score_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER PLAYER_BIU_TRG 
    BEFORE INSERT OR UPDATE ON player 
    FOR EACH ROW 
BEGIN
	IF
	    :new.player_id IS NULL
	THEN
	    :new.player_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER PLAYER_FACILITY_ASSOC_BIU_TRG 
    BEFORE INSERT OR UPDATE ON player_facility_assoc 
    FOR EACH ROW 
BEGIN
	IF
	    :new.player_facility_assoc_id IS NULL
	THEN
	    :new.player_facility_assoc_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER TEAM_BIU_TRG 
    BEFORE INSERT OR UPDATE ON team 
    FOR EACH ROW 
BEGIN
	IF
	    :new.team_id IS NULL
	THEN
	    :new.team_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/

CREATE OR REPLACE TRIGGER TEAM_LEAGUE_ASSOC_BIU_TRG 
    BEFORE INSERT OR UPDATE ON team_league_assoc 
    FOR EACH ROW 
BEGIN
	IF
	    :new.team_league_assoc_id IS NULL
	THEN
	    :new.team_league_assoc_id := kst_main_seq.nextval;
	END IF;
	
	IF
	    inserting
	THEN
	    :new.when_created := SYSDATE;
	    :new.created_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
	END IF;
	
	:new.when_updated := SYSDATE;
	
	:new.updated_by := nvl(sys_context('APEX$SESSION','APP_USER'),user);
END ; 
/



-- Oracle SQL Developer Data Modeler Summary Report: 
-- 
-- CREATE TABLE                            12
-- CREATE INDEX                             0
-- ALTER TABLE                             43
-- CREATE VIEW                              0
-- ALTER VIEW                               0
-- CREATE PACKAGE                           0
-- CREATE PACKAGE BODY                      0
-- CREATE PROCEDURE                         0
-- CREATE FUNCTION                          0
-- CREATE TRIGGER                          12
-- ALTER TRIGGER                            0
-- CREATE COLLECTION TYPE                   0
-- CREATE STRUCTURED TYPE                   0
-- CREATE STRUCTURED TYPE BODY              0
-- CREATE CLUSTER                           0
-- CREATE CONTEXT                           0
-- CREATE DATABASE                          0
-- CREATE DIMENSION                         0
-- CREATE DIRECTORY                         0
-- CREATE DISK GROUP                        0
-- CREATE ROLE                              0
-- CREATE ROLLBACK SEGMENT                  0
-- CREATE SEQUENCE                          0
-- CREATE MATERIALIZED VIEW                 0
-- CREATE SYNONYM                           0
-- CREATE TABLESPACE                        0
-- CREATE USER                              0
-- 
-- DROP TABLESPACE                          0
-- DROP DATABASE                            0
-- 
-- REDACTION POLICY                         0
-- 
-- ORDS DROP SCHEMA                         0
-- ORDS ENABLE SCHEMA                       0
-- ORDS ENABLE OBJECT                       0
-- 
-- ERRORS                                   0
-- WARNINGS                                 0
