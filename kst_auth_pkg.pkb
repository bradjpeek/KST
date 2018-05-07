create or replace package body kst_auth_pkg 
as 
 
/** 
* Constants -- NOTE: Fill these out later when known 
* 
* Constants are used to send password reset email 
*/ 
 
c_from_email constant varchar2(100) := 'no-reply@my.email'; 
c_website    constant varchar2(100) := 'my site'; 
c_hostname   constant varchar2(100) := 'my hostname'; 
 
/** 
* This (sha256 package) is used in place of dbms_crypto because dbms_crypto is not available in all 
* editions of Oracle. 
*/ 
function custom_hash( 
    p_username in varchar2, 
    p_password in varchar2) 
  return raw 
is 
  l_username varchar2(100); 
  l_password varchar2(100); 
  -- For the salt, any literal will do but it must be known when  
  l_salt     varchar2(30) := 'salt-n-peppa';  
begin 
  apex_debug.message(p_message => 'Begin custom_hash', p_level => 3) ; 
  -- This function should be wrapped, as the hash algorhythm is exposed here. 
  -- You can change the value of l_salt, but you much reset all of your passwords if you choose to do this. 
  l_username := upper(p_username); 
  l_password := upper(p_password); 
  l_password := sha256.sha256_digest(l_salt || l_username || l_password); 
  apex_debug.message(p_message => 'End custom_hash', p_level => 3) ; 
  return l_password; 
end custom_hash; 
 
 
/** 
* Reset password email 
*/ 
procedure mail_reset_password( 
  p_email    in varchar2, 
  p_url      in varchar2) 
is 
  l_body     clob;   
begin 
  apex_debug.message(p_message => 'Sending Reset password Link via email', p_level => 3) ;   
  l_body := '<p>Hi,</p> 
             <p>We received a request to reset your password in the KeepScore.Tennis app.</p> 
             <p><a href="'||p_url||'">Reset Now.</a></p> 
             <p>If you did not request this, you can simply ignore this email.</p> 
             <p>Kind regards,<br/> 
             KST Admin.</p>'; 
 
  apex_mail.send ( 
    p_to        => p_email, 
    p_from      => c_from_email, 
    p_body      => l_body, 
    p_body_html => l_body, 
    p_subj      => 'Reset password KeepScore.Tennis account'); 
 
  apex_mail.push_queue;     
 
exception 
when others  
then 
  raise_application_error( - 20002, 'Issue sending reset password email.') ; 
end mail_reset_password; 
 
 
/** 
*/ 
procedure create_account 
  ( 
    p_email      in varchar2 
  , p_password   in varchar2 
  , p_first_name in varchar2 
  , p_last_name  in varchar2 
  ) 
is 
  l_message varchar2(4000) ; 
  l_password raw(64) ; 
  l_user_id number; 
begin 
  apex_debug.message(p_message => 'Begin create_account', p_level => 3); 
 
  apex_debug.message(p_message => 'Check if email already exists', p_level => 3) ; 
 
  begin 
    select password_hash
      into l_password 
      from kst_app_user 
     where upper(email_address) = upper(p_email) ; 
      
    -- You will only arrive here if the above query returns a row, which in this 
    -- case means the email address is already in the KST_APP_USER table. 
    -- 
    l_message       := l_message || 'ERROR: Email address already registered.'; 
 
  exception 
  when no_data_found then 
    apex_debug.message(p_message => 'email doesn''t exist yet - continue...', p_level => 3) ; 
  end; 
 
  if l_message is null  
  then 
    apex_debug.message(p_message => 'Creating password hash', p_level => 3) ; 
    l_password := custom_hash(p_username => p_email, p_password => p_password) ; 
 
    apex_debug.message(p_message => 'insert row into KST_APP_USER', p_level => 3) ; 
    insert into kst_app_user  
       ( email_address, password_hash 
       , first_name, last_name  
       , is_member, is_admin 
       , member_since, member_expire_date 
       , search_allowed, autopay_allowed 
       ) 
    values  
      ( p_email, l_password 
      , p_first_name, p_last_name 
      , 'Y'                 -- is_member 
      , 'N'                 -- is_admin 
      , trunc(sysdate)      -- member_since 
      , trunc(sysdate + 30) -- member_expire_date 
      , 'Y'                 -- search_allowed 
      , 'N'                 -- autopay_allowed 
      ) ; 
  else 
    raise_application_error( -20001, l_message) ; 
  end if; 
   
  apex_authentication.post_login(p_username => p_email, p_password => p_password); 
 
  -- no activation email 
 
  apex_debug.message(p_message => 'End create_account', p_level => 3) ; 
end create_account; 
 
 
/** 
*/ 
function custom_authenticate 
  ( 
    p_username in varchar2, 
    p_password in varchar2 
  ) 
  return boolean 
is 
  l_password        varchar2(100) ; 
  l_stored_password varchar2(100) ; 
  l_boolean         boolean; 
begin 
  -- First, check to see if the user is in the user table and look up their password 
  select password_hash 
    into l_stored_password 
    from kst_app_user  
   where upper(email_address) = upper(p_username); 
  -- hash the password the person entered 
  l_password := custom_hash(p_username, p_password) ; 
  -- Finally, we compare them to see if they are the same and return either TRUE or FALSE 
  if l_password = l_stored_password then 
    return true; 
  else 
    return false; 
  end if; 
exception 
when no_data_found then 
  return false; 
end custom_authenticate; 
 
 
/** 
*/ 
procedure post_authenticate( 
    p_username in varchar2, 
    out_user_id out number, 
    out_time_zone out varchar2 
) 
is 
  l_id         number; 
  l_first_name varchar2(100) ; 
begin 
  select 1
    into l_id 
    from kst_app_user 
   where upper(email_address) = upper(p_username); 
  out_user_id        := l_id; 
 
end post_authenticate; 
 
 
/** 
*/ 
procedure request_reset_password( 
    p_email in varchar2) 
is 
  l_cnt               number(1); 
  l_verification_code number(6); 
  l_url               varchar2(200); 
begin 
  -- First, check to see if the user is in the user table 
  select 1 
    into l_cnt 
    from kst_app_user 
   where upper(email_address)    = upper(p_email); 
 
  dbms_random.initialize(to_char(sysdate, 'YYMMDDDSS')) ; 
  l_verification_code := round(dbms_random.value(1, 999999)) ; 
 
  l_url := apex_util.prepare_url(p_url => c_hostname||'f?p='||v('APP_ID')||':RESET_PWD:0::::P9999_ID,P9999_VC:' || p_email || ',' || l_verification_code, p_checksum_type => 1); 
   
  update kst_app_user 
     set password_reset_code  = l_verification_code 
   where upper(email_address) = upper(p_email); 
 
  mail_reset_password(p_email => p_email, p_url => l_url); 
 
exception 
when no_data_found then 
  raise_application_error( - 20001, 'Email address not registered.') ; 
end request_reset_password ; 
 
 
/** 
*/ 
function verify_reset_password( 
    p_email             in varchar2, 
    p_verification_code in number) 
  return boolean 
is 
  l_id number; 
begin 
  select 1 
    into l_id 
    from kst_app_user u 
   where u.password_reset_code = p_verification_code 
     and upper(u.email_address) = upper(p_email); 
 
  return TRUE; 
exception 
  when no_data_found 
  then 
    raise_application_error( - 20001, 'Invalid password request url.') ; 
    return FALSE; 
end verify_reset_password ; 
 
 
/** 
*/ 
procedure reset_password( 
    p_email    in varchar2, 
    p_password in varchar2) 
is 
  l_username        varchar2(100) ; 
  l_hashed_password varchar2(100) ; 
begin 
  select u.email_address 
    into l_username 
    from kst_app_user u
   where upper(u.email_address) = upper(p_email); 
 
  l_hashed_password := custom_hash(l_username, p_password) ; 
 
  update kst_app_user u
     set u.password_hash = l_hashed_password, 
         u.password_reset_code = null 
   where upper(u.email_address) = upper(p_email); 
    
end reset_password; 
 
 
/** 
*/ 
function is_administrator( 
    p_email in varchar2) 
  return boolean 
is 
  l_is_admin varchar2(1) ; 
begin 
  select is_admin 
    into l_is_admin 
    from kst_app_user a 
   where upper(a.email_address) = upper(p_email) ; 
  -- 
  return true; 
exception 
when no_data_found then 
  return false; 
end is_administrator; 
 
/** 
*/ 
function is_member( 
    p_email in varchar2) 
  return boolean 
is 
  l_is_member varchar2(1) ; 
begin 
  select 'Y' 
    into l_is_member 
    from kst_app_user a 
   where upper(a.email_address) = upper(p_email) 
     and a.is_member = 'Y'; 
  -- 
  return true; 
exception 
when no_data_found then 
  return false; 
end is_member; 
 
/** 
*/ 
function is_guest( 
    p_email in varchar2) 
  return boolean 
is 
  l_is_guest varchar2(1) ; 
begin 
  select 'Y' 
    into l_is_guest 
    from kst_app_user a 
   where upper(a.email_address) = upper(p_email) 
     and a.is_member = 'N' 
     and a.first_name = 'Guest'; 
  -- 
  return true; 
exception 
when no_data_found then 
  return false; 
end is_guest; 
 
end kst_auth_pkg; 
/
