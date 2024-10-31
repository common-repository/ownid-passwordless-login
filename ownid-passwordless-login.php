<?php
defined('ABSPATH') or die("exit");

/*
Plugin Name: OwnID Passwordless Login
Description: Passwordless login for Wordpress and WooCommerce. Let your users authenticate without having to remember a password. It supports Apple Passkeys.
Version: 1.3.4
Tested Up To: 6.4
Author: OwnID
Author URI: https://ownid.com
License: GPL2
*/

function ownid_passwordless_active()
{
    add_option(  'ownid_infoTooltip_position', "top" );
    add_option(  'ownid-admin-auth-button', "button-fingerprint" );
    add_option(  'ownid-account-auth-button', "button-fingerprint" );
    add_option(  'ownid-env', "prod" );
}
register_activation_hook(__FILE__,'ownid_passwordless_active');

function ownid_passwordless_add_plugin_action_links($links)
{

    $links['documentation'] = sprintf(
        '<a href="%1$s" target="_blank" style="color: #42b983; font-weight: bold;">%2$s</a>',
        'https://docs.ownid.com?utm_source=plugin_page',
        'Documentation'
    );

    return $links;
}
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'ownid_passwordless_add_plugin_action_links');


function ownid_passwordless_network_pages() {
	add_submenu_page( 'settings.php', 'OwnID', 'OwnID', 'manage_options', 'ownid', 'wp_cache_manager' );
}
add_action( 'network_admin_menu', 'ownid_passwordless_network_pages' );

/**
 * We set the Endpoints routes and their callbacks
 */
add_action( 'rest_api_init', function () {
  register_rest_route( 'ownid/v1', '/getOwnIDDataByLoginID', array(
    'methods' => 'POST',
    'callback' => 'getOwnIDDataByLoginID',
    'permission_callback' => '__return_true',
  ) );
} );

add_action( 'rest_api_init', function () {
    register_rest_route( 'ownid/v1', '/setOwnIDDataByLoginID', array(
      'methods' => 'POST',
      'callback' => 'setOwnIDDataByLoginID',
      'permission_callback' => '__return_true',
    ) );
  } );

  add_action( 'rest_api_init', function () {
    register_rest_route( 'ownid/v1', '/getSessionByLoginID', array(
      'methods' => 'POST',
      'callback' => 'getSessionByLoginID',
      'permission_callback' => '__return_true',
    ) );
  } );

  add_action( 'rest_api_init', function () {
    register_rest_route( 'ownid/v1', '/login-with-jwt', array(
      'methods' => 'POST',
      'callback' => 'ownid_passwordless_login_with_jwt',
      'permission_callback' => '__return_true',
    ) );
  } );

  add_action( 'rest_api_init', function () {
    register_rest_route( 'ownid/v1', '/createOwnIDAccount', array(
      'methods' => 'POST',
      'callback' => 'createOwnIDAccount',
      'permission_callback' => '__return_true',
    ) );
  } );

/**
 * Verifies that the request comes from OwnID Server - INTERNAL
 *
 * @param WP_REST_Request Request from OwnID Server
 * @return boolean return true if signature matches or false if the verification fails
 */
function ownid_passwordless_requestVerification(WP_REST_Request $request){

  if(isset($_SERVER["HTTP_OWNID_SIGNATURE"]) && isset($_SERVER["HTTP_OWNID_TIMESTAMP"])){

    //We get the headers;
    $ownIDSig = sanitize_text_field($_SERVER['HTTP_OWNID_SIGNATURE']);
    $ownIDTimestamp = sanitize_text_field($_SERVER['HTTP_OWNID_TIMESTAMP']);

    $key= get_option('ownid_shared_secret');
    $keyRaw = base64_decode($key);

    $entityBody = file_get_contents('php://input');

    $stringToEncode = $entityBody.".".$ownIDTimestamp;

    $sig = hash_hmac('sha256', $stringToEncode, $keyRaw);

    //We convert the hex returned from hash_hmac to binary and then we encode it in base64
    $sig =  base64_encode(hex2bin($sig));

    if($sig === $ownIDSig){

        //Request comes from OwnID server, we return OK
        return true;

    }else{
        return false;
    }

    }else{

        //If OwnID headers are missing we don't process the request
        return false;

    }

}

/**
 * Get the OwnIDData by loginID
 *
 * @param WP_REST_Request Request from OwnID Server
 * @return object return OwnID payload or 404 message if user not found
 */
function getOwnIDDataByLoginID( WP_REST_Request $request ) {

    //If the headers signature verification fails, we exit
    if(!ownid_passwordless_requestVerification($request)===true){
      exit("forbidden");
    }

    header('Content-Type: application/json; charset=utf-8');

    $email = sanitize_email($request['loginId']);

    $user = get_user_by('email', $email);

    //If there's no user we return 404
    if(!$user){

      $response["errorCode"] = 404;
      $response["errorMessage"] = "User not found";

      return $response;
    }

    $user_id = $user->ID;

    $meta = get_user_meta($user_id, 'ownIdData', true);

    $response["ownIdData"] = $meta;

    return $response;
}

/**
 * Set the OwnIDData by loginID
 *
 * @param WP_REST_Request Request from OwnID Server
 * @return object return empty body with 204 errorCode
 */
function setOwnIDDataByLoginID( WP_REST_Request $request ) {

    //If the headers verification fails, we exit
    if(!ownid_passwordless_requestVerification($request)===true){
        exit("forbidden");
    }

    $email = sanitize_email($request['loginId']);
    $ownIDPayload = sanitize_text_field($request['ownIdData']);
    $user = get_user_by('email', $email);
    $user_id = $user->ID;

    $result = update_user_meta( $user_id, 'ownIdData', $ownIDPayload );

    return new WP_REST_Response(null, 204);
}

/**
 * Get the user JWT token by loginID
 *
 * @param WP_REST_Request Request from OwnID Server
 * @return object containing the JWT token
 */
function getSessionByLoginID( WP_REST_Request $request ) {

    //If the headers verification fails, we exit
    if(!ownid_passwordless_requestVerification($request)===true){
      exit("forbidden");
    }

    $param = sanitize_email($request['loginId']);
    $secret = get_option('ownid_shared_secret');

    $user = get_user_by('email', $param);

    //If there's no user we return 404
    if(!$user){

      $response["errorCode"] = 404;
      $response["errorMessage"] = "User not found";

      return $response;
    }

    $user_id = $user->ID;

    set_user_activated_if_needed($user_id);

    // Create token header as a JSON string
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);

    // Create token payload as a JSON string
    // TODO - Set a proper expiration time for the JWT
    $t=time()+1000;
    $payload = json_encode(['sub' => $user_id, 'exp' => $t]);

    // Encode Header to Base64Url String
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));

    // Encode Payload to Base64Url String
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

    // Create Signature Hash
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secret, true);

    // Encode Signature to Base64Url String
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

    // Create JWT
    $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

    $response["token"] = $jwt;

    return $response;
}

/**
 * Get the user JWT token by loginID
 *
 * @param WP_REST_Request Request from OwnID Server
 * @return object containing the JWT token
 */
function createOwnIDAccount( WP_REST_Request $request ) {

   //TO-DO check OwnID Headers
   //If the headers verification fails, we exit
   if(!ownid_passwordless_requestVerification($request)===true){
        exit("forbidden");
   }

   // Get email from request
   $email = sanitize_email($request['loginId']);

   // Check if email is already registered
   if ( email_exists( $email ) ) {
       return new WP_REST_Response( 'Email already registered', 400 );
   }

   // Validate email
   if(!is_email( $email )){
       return new WP_REST_Response( 'Invalid email address', 400 );
   }

   // Create user data
   $user_data = array(
       'user_login' => $email,
       'user_email' => $email,
       'user_pass'  => wp_generate_password(),
   );

   // Create user
   $user_id = wp_insert_user( $user_data );

   if ( ! is_wp_error( $user_id ) ) {

          //Check if WooCommerce is installed
          if ( class_exists( 'WooCommerce' ) ) {
            // Give new user the "customer" role
            $user = new WP_User( $user_id );
            $user->set_role( 'customer' );
          }

       return new WP_REST_Response( null, 200 );
   } else {
       return new WP_REST_Response( $user_id->get_error_message(), 400 );
   }

}

/**
 * Authenticates the user with the JWT generated
 *
 * @param WP_REST_Request Request from OwnID Server
 *
 */
function ownid_passwordless_login_with_jwt( WP_REST_Request $request ) {

  function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
  }

    $secret = get_option('ownid_shared_secret');
    $jwt = $request["jwt"];
    $is_valid = false;

    $tokenParts = explode('.', $jwt);
    $header = base64_decode($tokenParts[0]);
    $payload = base64_decode($tokenParts[1]);
    $signature_provided = $tokenParts[2];

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode($payload)->exp;
    $is_token_expired = ($expiration - time()) < 0;

    // build a signature based on the header and payload using the secret
    $base64_url_header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64_url_payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    $signature = hash_hmac('SHA256', $base64_url_header. "." .$base64_url_payload, $secret, true);
    $base64_url_signature  = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

    // verify it matches the signature provided in the jwt
    $is_signature_valid = ($base64_url_signature  === $signature_provided);

    // verify it matches the signature provided in the jwt
    $is_signature_valid = ($base64_url_signature  === $signature_provided);

    if ($is_token_expired || !$is_signature_valid) {

      $is_valid = false;

    } else {

      $is_valid = true;

    }

    //If the JWT verification is correct
    if($is_valid){

      //Token is valid so we extract the sub
      $user_id =json_decode($payload)->sub;

      //and we log the correspondent user
      wp_clear_auth_cookie();
      wp_set_current_user ( $user_id );
      wp_set_auth_cookie  ( $user_id );
      $redirect_to = user_admin_url();
      wp_safe_redirect( $redirect_to );
      exit();

    }

}

function set_user_activated_if_needed($user_id) {
    $meta_key = 'alg_wc_ev_is_activated';
    $current_value = get_user_meta($user_id, $meta_key, true);
    error_log("set $meta_key for $user_id with $current_value");
    if ($current_value == 0) {
        update_user_meta($user_id, $meta_key, 1);
    }
}

/**
 * Load the OwnID library in the FE
 *
 */
function init_OwnID() {

    $appId = esc_attr(get_option('ownid_appid'));

    $ownidEnv = esc_attr(get_option('ownid-env'));
    $ownidBaseUrl = 'cdn.ownid.com';

    if ($ownidEnv != 'prod' && $ownidEnv != '') {
        $ownidBaseUrl = "cdn.$ownidEnv.ownid.com";
    }

    if ($ownidEnv == 'prod-eu') {
        $ownidBaseUrl = 'cdn.ownid-eu.com';
    }

     $isLoggedIn = is_user_logged_in() ? 'true' : 'false';

    echo "<script type='text/javascript'>
    ((o,w,n,i,d)=>{o[i]=o[i]||(async(...a)=>((o[i].q=o[i].q||[]).push(a),{error:null,data:null})),
    (d=w.createElement('script')).src='https://$ownidBaseUrl/sdk/'+n,d.async=1,w.head.appendChild(d)})
    (window,document,'$appId','ownid');
    ownid('init', { appId: '$appId', checkSession: () => $isLoggedIn });
    </script>";
}


// Add hook for admin <head></head>
add_action( 'admin_head', 'init_OwnID', 1 );
// Add hook for front-end <head></head>
add_action( 'wp_head', 'init_OwnID', 1 );
add_action( 'login_enqueue_scripts', 'init_OwnID', 1);

    /**
     * creates a hidden field to store the OwnIDData during WooCommerce route registration
     *
     */
  function ownid_passwordless_wooc_extra_register_fields() {

    ?>
    <p class="form-row form-row-wide">
    <input type="hidden" name="ownIdData" id="ownIdData" value=""/>
    <div class="clear"></div>
    <?php
}
add_action( 'woocommerce_register_form_start', 'ownid_passwordless_wooc_extra_register_fields' );


    /**
     * Saves the OwnIDData in the account
     *
     */
  function ownid_passwordless_registration_save( $user_id ) {

    if( isset( $_POST['ownIdData']))
    {
      //Sanitize
      $ownIdData = sanitize_text_field($_POST['ownIdData']);

      //Validate
      if (preg_match('/^ownid==.*$/', $ownIdData) && !empty($ownIdData)){

         update_user_meta( $user_id, 'ownIdData', $ownIdData);

      }else{

         update_user_meta( $user_id, 'ownIdData', "");

      }

    }else{
      update_user_meta( $user_id, 'ownIdData', "");
    }

  }
  add_action( 'user_register', 'ownid_passwordless_registration_save', 10, 1 );
  add_action( 'user_update', 'ownid_passwordless_registration_save', 10, 1 );


/**
 * Adds OwnID Login+Register methods to the WP Footer
 *
 */
function ownid_passwordless_add_script_to_account_page() {

    ?>
    <script type="text/javascript">

            var email_field_id_1 = 'username';
            var pass_field_id_1 = 'password';
            var email_field_id_2 = '<?php echo esc_attr(get_option('ownid-extra-email-field-id'))?>' || '';
            var pass_field_id_2 = '<?php echo esc_attr(get_option('ownid-extra-pass-field-id'))?>' || '';
            var element_positioning_selector = '<?php echo esc_attr(get_option('ownid-element-positioning-selector'))?>' || '';

            if(document.getElementById(email_field_id_1) || document.getElementById(email_field_id_2)){

              var loginVariant = '<?php echo esc_attr(get_option('ownid-account-auth-button'))?>';
              if(loginVariant ===''){
                loginVariant = 'button-fingerprint';
              }
              var loginInfoTooltip = true;

              //We adjust the account Login Page UI to match the variant of no-password login
              if(loginVariant === 'ownid-account-auth-button'){
                loginVariant = 'ownid-auth-button';
                   document.getElementById('password').style = 'display:none;';
                   document.querySelector('.woocommerce-form-login > p > button').remove();
                   document.querySelector('.woocommerce-form-login > .lost_password').remove();
                   document.querySelector('.woocommerce-form-login > p > label[for="password"]').remove();
                   document.querySelector('.woocommerce-form-login > p > label[for="username"]').textContent = 'Email address';
                   setTimeout(() => {
                    if (document.location.pathname.includes('checkout') && window.innerWidth > 780) {
                        document.querySelector('.woocommerce-form-login .password-input').style.cssText += 'margin-top: 37px;';
                    }

                    document.querySelector('.woocommerce-form-login .show-password-input').remove();
                   }, 100);
                   loginInfoTooltip = false;
                 // Your CSS as text
                  var styles = `

                      ownid-auth-button {
                          width:100%;
                          z-index: 990;
                          height: 49px !important;
                      }

                      ownid-auth-button-faceid {
                          width: 100%;
                          z-index: 990;
                          height: 49px !important;
                      }

                      .woocommerce-form-register {
                          margin-top: -18px;
                      }
                  `
                  var styleSheet = document.createElement("style")
                  styleSheet.innerText = styles
                  document.head.appendChild(styleSheet)
              }

              function init_OwnID(loginIdFieldId, passFieldId, injectCustomElementPositioningSelector){
                  ownid('login', {
                      variant: loginVariant,
                      infoTooltip: loginInfoTooltip,
//                       widgetPosition: '<?php echo esc_attr(get_option('ownid_widget_position')); ?>',
//                       infoTooltipPosition:'<?php echo esc_attr(get_option('ownid_infoTooltip_Position')); ?>',
                      passwordToggle: injectCustomElementPositioningSelector && element_positioning_selector != '' ?
                       element_positioning_selector : '.show-password-input',
                      language:'<?php echo esc_attr(substr(get_locale(), 0, 2));?>',
                      loginIdField: document.getElementById(loginIdFieldId),
                      passwordField: document.getElementById(passFieldId),
                      onError: (error) => console.log(error),
                      onLogin: function (data) {

                          var xhr = new XMLHttpRequest();
                          xhr.open('POST', '<?php echo esc_url(get_home_url()) ?>/wp-json/ownid/v1/login-with-jwt', true);
                          xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                          xhr.onload = function () {
                              // do something to response
                              location.reload();
                          };
                          xhr.send('jwt='+data.token);

                      }

                  });
              }

              setTimeout(function() {
                  document.getElementById(email_field_id_1) && init_OwnID(email_field_id_1, pass_field_id_1);
                  document.getElementById(email_field_id_2) && init_OwnID(email_field_id_2, pass_field_id_2, true);
              }, 500);
            }

            if(document.getElementById('reg_password')){

              var regVariant = '<?php echo esc_attr(get_option('ownid-account-auth-button'))?>';
              if(regVariant ===''){
                regVariant = 'button-fingerprint';
              }
              var regInfoTooltip = true;

    // At the moment, don't apply no-password variation on registration


              //We adjust the account Registration Page UI to match the variant of no-password login
//               if(regVariant === 'ownid-account-auth-button'){
//                 regVariant = 'ownid-auth-button';
//                 document.getElementById('reg_password').style = 'display:none;';
//                 document.getElementById('reg_password').value = '<?php echo wp_generate_password();?>'
//                 document.querySelector('.woocommerce-form-register > p > label[for="reg_password"]').remove();
//                 regInfoTooltip = false;
//               }

                regVariant = 'button-fingerprint';
                ownid('register', {
                  variant: regVariant,
                  infoTooltip: regInfoTooltip,
//                   widgetPosition: '<?php echo esc_attr(get_option('ownid_widget_position')); ?>',
//                   infoTooltipPosition:'<?php echo esc_attr(get_option('ownid_infoTooltip_Position')); ?>',
                  passwordToggle:'.show-password-input',
                  language:'<?php echo substr(get_locale(), 0, 2);?>',
                  loginIdField: document.getElementById('reg_email'),
                  passwordField: document.getElementById('reg_password'),
                  onError: (error) => console.log(error),
                  onRegister: function(data){
                    document.getElementById("ownIdData").value = data.data;
                  }
              });
            }

    </script>

<?php
    //}
  }
  //We need to ensure is the last action executed
  add_action( 'wp_footer', 'ownid_passwordless_add_script_to_account_page' , 9999999);

  /**
 * Adds OwnID Login to WP Admin
 *
 */
function ownid_passwordless_add_script_to_admin_login_page() {

  ?>
  <script type="text/javascript">

          if(document.getElementById('user_pass')){
          //Check to load the script is the user is on the login page

          var variant = '<?php echo esc_attr(get_option('ownid-admin-auth-button'))?>';
          if(variant ===''){
            variant = 'button-fingerprint';
          }
          var infotooltip = true;

          //We adjust the Admin Login Page UI to match the variant of no-password login
          if(variant === 'ownid-admin-auth-button'){
            variant = 'ownid-auth-button';
            document.getElementsByTagName('label')[1].remove();
            document.getElementById('user_pass').style = 'display:none;';
            document.querySelector('#loginform > div > div > button > span').remove();
            document.querySelector('#loginform > div > div > button').remove();
            document.getElementsByTagName('label')[0].innerHTML = 'Email:' // TODO - translations
            document.getElementById('wp-submit').remove();
            document.getElementsByClassName('forgetmenot')[0].remove();
            infotooltip = false;
             // Your CSS as text
              var styles = `
                    ownid-auth-button {
                      width:100%;
                      z-index: 999;
                    }

                    ownid-auth-button-faceid {
                      width: 100%;
                      z-index: 999;
                    }

                    .user-pass-wrap {
                    padding-bottom:-10px;
                    }
              `

              var styleSheet = document.createElement("style")
              styleSheet.innerText = styles
              document.head.appendChild(styleSheet)
          }


                ownid('login', {
                  variant: variant,
                  infoTooltip: infotooltip,
                  infoTooltipPosition:'start',
                  widgetPosition: 'start',
                  tooltip: {position:'start'},
                  passwordToggle:'.show-password-input',
                  language:'<?php echo substr(get_locale(), 0, 2);?>',
                  loginIdField: document.getElementById('user_login'),
                  passwordField: document.getElementById('user_pass'),
                  onError: (error) => console.log(error),
                  onLogin: function (data) {

                      var xhr = new XMLHttpRequest();
                      xhr.open('POST', '<?php echo esc_url(get_home_url()) ?>/wp-json/ownid/v1/login-with-jwt', true);
                      xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                      xhr.onload = function () {
                          // do something to response
                          var redirectURL = "<?php echo esc_url(get_option('ownid-custom-redirect'))?>";
                          if(redirectURL ===""){
                            redirectURL = "<?php echo esc_url(admin_url())?>";
                          }
                          window.location.href = redirectURL;
                      };
                      xhr.send('jwt='+data.token);

                  }

              });

          }
  </script>
<?php

}
add_action( 'login_footer', 'ownid_passwordless_add_script_to_admin_login_page' );


function ownid_passwordless_my_login_stylesheet() {
  wp_enqueue_style( 'custom-login', plugin_dir_url( __FILE__ ) . 'css/style-login.css' );
}
add_action( 'login_enqueue_scripts', 'ownid_passwordless_my_login_stylesheet' , 10);
add_action( 'admin_enqueue_scripts', 'ownid_passwordless_my_login_stylesheet', 10 );


function ownid_passwordless_apd_settings_link( array $links ) {
    $url = esc_url(get_admin_url()) . "options-general.php?page=ownid";
    $settings_link = '<a href="' . $url . '">' . __('Settings', 'textdomain') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
  }
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'ownid_passwordless_apd_settings_link' );

/**
 * Register the OwnID settings
 *
 */
function ownid_passwordless_register_settings() {

  register_setting( 'ownid_options_group', 'ownid_appid', 'ownid_passwordless_appid_validation' );
  register_setting( 'ownid_options_group', 'ownid_shared_secret', 'ownid_passwordless_secret_validation' );
  register_setting( 'ownid_options_group', 'ownid_infoTooltip_Position', 'ownid_passwordless_tooltip_position_validation' );
  register_setting( 'ownid_options_group', 'ownid_widget_position', 'ownid_passwordless_widget_position_validation' );
  register_setting( 'ownid_options_group', 'ownid-admin-auth-button', 'ownid_passwordless_admin_variant_validation' );
  register_setting( 'ownid_options_group', 'ownid-account-auth-button', 'ownid_passwordless_account_variant_validation' );
  register_setting( 'ownid_options_group', 'ownid-custom-redirect', 'ownid_passwordless_redirectURL_validation' );
  register_setting( 'ownid_options_group', 'ownid-env', 'ownid_env_validation' );
  register_setting( 'ownid_options_group', 'ownid-extra-email-field-id', 'ownid_passwordless_login_form_field_ids_validation' );
  register_setting( 'ownid_options_group', 'ownid-extra-pass-field-id', 'ownid_passwordless_login_form_field_ids_validation' );
  register_setting( 'ownid_options_group', 'ownid-element-positioning-selector', 'ownid_ownid_element_positioning_selector_validation' );

}
add_action( 'admin_init', 'ownid_passwordless_register_settings' );


function ownid_passwordless_login_form_field_ids_validation($input) {
      return $input;
}

function ownid_ownid_element_positioning_selector_validation($input) {
      return $input;
}

//Verification of the App ID
function ownid_passwordless_appid_validation($input){

  if(empty($input)){
        //Show error
        add_settings_error('ownid_appid','error 001','The App ID cannot be empty.','error');
        return "";
  }

  if (preg_match('/^[A-Za-z0-9]*$/', $input) && !empty($input)){

    add_settings_error('ownid_appid','error 001','The App ID is correct!','success');
    return $input;

  }else{
    //Show error
    add_settings_error('ownid_appid','error 001','The App ID is not valid.','error');
    return "";
  }

}

//Validation for the ownid_shared_secret input
function ownid_passwordless_secret_validation($input){

  if(empty($input)){
    //Show error
    add_settings_error('ownid_shared_secret','error 001','The Shared Secret cannot be empty.','error');
    return "";
  }

  if (preg_match('/^(?:[a-zA-Z0-9+\/]{4})*(?:|(?:[a-zA-Z0-9+\/]{3}=)|(?:[a-zA-Z0-9+\/]{2}==)|(?:[a-zA-Z0-9+\/]{1}===))$/', $input) && !empty($input)){

    return $input;

  }else{
    //Show error
    add_settings_error('ownid_shared_secret','error 001','The Shared Secret is not valid.','error');
    return "";
  }

}

//Validation for the variant input
function ownid_passwordless_admin_variant_validation($input){


    if ($input !== 'button-fingerprint' && $input !== 'ownid-admin-auth-button') {
       //Show error
       add_settings_error('ownid-admin-auth-button','error 003','Invalid string. String must be "button-fingerprint" or "ownid-admin-auth-button".','error');
       return "";
    }

    return $input;
}

//Validation for the variant input
function ownid_passwordless_account_variant_validation($input){


    if ($input !== 'button-fingerprint' && $input !== 'ownid-account-auth-button') {
       //Show error
       add_settings_error('ownid-account-auth-button','error 003','Invalid string. String must be "button-fingerprint" or "ownid-account-auth-button".','error');
       return "";
    }

    return $input;
}

function ownid_env_validation($input){
    return $input;
}

//Validation for the Widget Position
function ownid_passwordless_widget_position_validation($input){

  if (preg_match('/^(start|end)$/', $input) && !empty($input)){

    return $input;

  }else{
    //Show error
    add_settings_error('ownid_widget_position','error 001','The Widget Position is not valid.','error');
    return "";
  }

}

//Validation for the Tool tip Position
function ownid_passwordless_tooltip_position_validation($input){

  if (preg_match('/^(start|end|top|bottom)$/', $input) && !empty($input)){

    return $input;

  }else{
    //Show error
    add_settings_error('ownid_infoTooltip_Position','error 001','The Tooltip Position is not valid.','error');
    return "";
  }

}

//Verification of the Redirection URL
function ownid_passwordless_redirectURL_validation($input){

  if($input === ""){
    return "";
  }

  if (wp_http_validate_url($input)){

    return sanitize_url($input);

  }else{
    //Show error
    add_settings_error('ownid-custom-redirect','error 002','The Redirect URL is invalid.','error');
    return "";
  }

}


function ownid_passwordless_register_options_page() {
  add_options_page('OwnID Options', 'OwnID Configuration', 'manage_options', 'ownid', 'ownid_passwordless_options_page');
}
add_action('admin_menu', 'ownid_passwordless_register_options_page');


  function ownid_passwordless_options_page()
  {

  // check user capabilities
  if ( ! current_user_can( 'manage_options' ) ) { return; }

  ?>
    <div class = "wrap">
      <h1>OwnID Settings</h1>
      <form method="post" action="options.php">
      <?php settings_fields( 'ownid_options_group' ); ?>
      <table class="form-table" role="presentation">
        <tr valign="top">
          <th scope="row"><label for="ownid_appid">App ID</label></th>
          <td>
            <input type="text" id="ownid_appid" name="ownid_appid" class="regular-text" value="<?php echo esc_attr(get_option('ownid_appid')); ?>" />
            <p class="description" id="tagline-description">You can get this parameter and the Shared Secret from <a href="https://console.ownid.com/registration?utm_source=wordpress" target="_new">OwnID Console</a>.</p>
          </td>

        </tr>
        <tr valign="top">
          <th scope="row"><label for="ownid_shared_secret">Shared secret</label></th>
          <td><input type="password" id="ownid_shared_secret" class="regular-text" name="ownid_shared_secret" value="<?php echo esc_attr(get_option('ownid_shared_secret')); ?>" /></td>
        </tr>
        <tr valign="top">
          <th scope="row"><h2>UI Settings WordPress</h2></th>
          <td></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label for="ownid-admin-auth-button">Remove Password Field</label></th>
            <td>
            <select name="ownid-admin-auth-button" id="ownid-admin-auth-button">
              <option value="button-fingerprint" <?php if(esc_attr(get_option('ownid-admin-auth-button')) === "button-fingerprint") echo 'selected' ?>>No</option>
              <option value="ownid-admin-auth-button" <?php if(esc_attr(get_option('ownid-admin-auth-button')) === "ownid-admin-auth-button") echo 'selected' ?>>Yes</option>
             </select>
             <p class="description" id="tagline-description">Remove the password option from the form.</p>
            </td>
         </tr>
         <tr valign="top">
            <th scope="row"><label for="ownid-custom-redirect">Redirection URL after Login</label></th>
            <td>
              <input type="text" id="ownid-custom-redirect" name="ownid-custom-redirect" class="regular-text" value="<?php echo esc_url(get_option('ownid-custom-redirect')); ?>" />
              <p class="description" id="tagline-description">Choose where to redirect a user after a successful passwordless login.</p>
            </td>
         </tr>
        <tr valign="top">
          <th scope="row"><h2>UI Settings WooCommerce</h2></th>
          <td></td>
        </tr>
        <tr valign="top">
            <th scope="row"><label for="ownid-account-auth-button">Remove Password Field</label></th>
            <td>
            <select name="ownid-account-auth-button" id="ownid-account-auth-button">
              <option value="button-fingerprint" <?php if(esc_attr(get_option('ownid-account-auth-button')) === "button-fingerprint") echo 'selected' ?>>No</option>
              <option value="ownid-account-auth-button" <?php if(esc_attr(get_option('ownid-account-auth-button')) === "ownid-account-auth-button") echo 'selected' ?>>Yes</option>
             </select>
             <p class="description" id="tagline-description">Remove the password option from the form.</p>
            </td>
         </tr>
         <tr valign="top">
            <th scope="row"><label for="ownid_widget_position">Widget Position</label></th>
            <td>
            <select name="ownid_widget_position" id="ownid_widget_position">
              <option value="start" <?php if(esc_attr(get_option('ownid_widget_position')) === "start") echo 'selected' ?>>Start</option>
              <option value="end" <?php if(esc_attr(get_option('ownid_widget_position')) === "end") echo 'selected' ?>>End</option>
             </select>
             <p class="description" id="tagline-description">Change the position of widget.</p>
            </td>
         </tr>
          <tr valign="top">
            <th scope="row"><label for="ownid_infoTooltip_Position">Tooltip Position</label></th>
            <td>
            <select name="ownid_infoTooltip_Position" id="ownid_infoTooltip_Position">
              <option value="top" <?php if(esc_attr(get_option('ownid_infoTooltip_Position')) === "top") echo 'selected' ?>>Top</option>
              <option value="start" <?php if(esc_attr(get_option('ownid_infoTooltip_Position')) === "start") echo 'selected' ?>>Start</option>
              <option value="end" <?php if(esc_attr(get_option('ownid_infoTooltip_Position')) === "end") echo 'selected' ?>>End</option>
              <option value="bottom" <?php if(esc_attr(get_option('ownid_infoTooltip_Position')) === "bottom") echo 'selected' ?>>Bottom</option>
            </select>
            <p class="description" id="tagline-description">Change the position of the tooltip.</p>
            </td>
          </tr>
          <tr valign="top">
            <th scope="row"><label for="ownid-extra-email-field-id">Custom Form: Email field ID</label></th>
            <td>
              <input type="text" id="ownid_appid" name="ownid-extra-email-field-id" class="regular-text" value="<?php echo esc_attr(get_option('ownid-extra-email-field-id')); ?>" />
              <p class="description" id="tagline-description">If you have an extra login form besides the default WooCommerce one and you want OwnID plugin to be injected into it, insert its email field id.</p>
            </td>
          </tr>
          <tr valign="top">
            <th scope="row"><label for="ownid-extra-pass-field-id">Custom Form: Password field ID</label></th>
            <td>
              <input type="text" id="ownid_appid" name="ownid-extra-pass-field-id" class="regular-text" value="<?php echo esc_attr(get_option('ownid-extra-pass-field-id')); ?>" />
              <p class="description" id="tagline-description">If you have an extra login form besides the default WooCommerce one and you want OwnID plugin to be injected into it, insert its password field id.</p>
            </td>
          </tr>
          </tr>
          <tr valign="top">
            <th scope="row"><label for="ownid-element-positioning-selector">Adjust Element Positioning</label></th>
            <td>
              <input type="text" id="ownid_appid" name="ownid-element-positioning-selector" class="regular-text" value="<?php echo esc_attr(get_option('ownid-element-positioning-selector')); ?>" />
              <p class="description" id="tagline-description">Specify a selector for inline elements in the password field, such as toggles, labels, or placeholders that require repositioning for optimal widget integration.</p>
            </td>
          </tr>
          <tr valign="top" style="display:none;">
            <th scope="row"><label for="ownid-env">env</label></th>
            <td>
            <select name="ownid-env" id="ownid-env">
              <option value="prod" <?php if(esc_attr(get_option('ownid-env')) === "prod") echo 'selected' ?>>prod</option>
              <option value="prod-eu" <?php if(esc_attr(get_option('ownid-env')) === "prod-eu") echo 'selected' ?>>prod-eu</option>
              <option value="uat" <?php if(esc_attr(get_option('ownid-env')) === "uat") echo 'selected' ?>>uat</option>
              <option value="staging" <?php if(esc_attr(get_option('ownid-env')) === "staging") echo 'selected' ?>>staging</option>
              <option value="dev" <?php if(esc_attr(get_option('ownid-env')) === "dev") echo 'selected' ?>>dev</option>
            </select>
            <p class="description" id="tagline-description">environment</p>
            </td>
          </tr>
        <tr valign="top">
          <th scope="row" colspan="2"><p class="description" id="tagline-description">Feel free to submit your questions and feedback to contact@ownid.com</p></th>
          <td>
          </td>
        </tr>
        </table>
        <?php  submit_button(); ?>
      </form>
    </div>
  <?php
  } 
?>
