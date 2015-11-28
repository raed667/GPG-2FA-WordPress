<?php
/**
 * Class for managing GPG 2FA
 *
 * @since 0.1-dev
 *
 * @package Two_Factor
 */
class Two_Factor_GPG extends Two_Factor_Provider {

	/**
	 * The user meta gpg key.
	 * @type string
	 */
	const GPG_META_KEY = '_two_factor_gpg';

	/**
	 * The user meta gpg key.
	 * @type string
	 */
	const GPG_TOKEN_META_KEY = '_two_factor_gpg_token';

	/**
	 * Ensures only one instance of this class exists in memory at any one time.
	 *
	 * @since 0.1-dev
	 */
	static function get_instance() {
		static $instance;
		$class = __CLASS__;
		if ( ! is_a( $instance, $class ) ) {
			$instance = new $class;
		}
		return $instance;
	}

	/**
	 * Class constructor.
	 *
	 * @since 0.1-dev
	 */
	protected function __construct() {
		add_action( 'two-factor-user-options-' . __CLASS__, array( $this, 'user_options' ) );
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );
		add_action( 'wp_ajax_two_factor_set_key', array( $this, 'ajax_set_key' ) );

		return parent::__construct();
	}

	/**
	 * Displays an admin notice when backup codes have run out.
	 *
	 * @since 0.1-dev
	 */
	public function admin_notices() {
		$user = wp_get_current_user();

		// Return if the provider is not enabled.
		if ( ! in_array( __CLASS__, Two_Factor_Core::get_enabled_providers_for_user( $user->ID ) ) ) {
			return;
		}
	}

	/**
	 * Returns the name of the provider.
	 *
	 * @since 0.1-dev
	 */
	public function get_label() {
		return _x( 'GPG 2FA', 'Raed Chammam' );
	}

	/**
	 * Whether this Two Factor provider is configured and a key is available for the user specified.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function is_available_for_user( $user ) {
		// Does this user have a key
		$key = get_user_meta( $user->ID, self::GPG_META_KEY, true );
		if($key == false || $key ==""){
			return false;
		}
		return true;
	}

	/**
	 * Inserts markup at the end of the user profile field for this provider.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function user_options( $user ) {
		$ajax_nonce = wp_create_nonce( 'two-factor-backup-codes-set-key-' . $user->ID );

		$key = get_user_meta( $user->ID, self::GPG_META_KEY, true );
		$key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"."\n\n".$key."\n-----END PGP PUBLIC KEY BLOCK-----";
		?>
		<p id="two-factor-gpg-form">
			<textarea wrap="on" placeholder="Public Key" id="publicKey"><?php esc_html_e($key); ?></textarea>
			<br>
			<button type="button" class="button button-two-factor-set-key button-secondary hide-if-no-js">
				<?php esc_html_e( 'Upload public key' ); ?>
			</button>
		</p>
		<div class="two-factor-gpg-key" style="display:none;"></div>

		<script type="text/javascript">
			( function( $ ) {
				$( '.button-two-factor-set-key' ).click( function() {
					var $key = $("#publicKey").val();

					if($key.length==0){
						//@TODO : better key cheking
						alert("Public Key shouldn't be empty");
						return;
					}

					$.ajax( {
						method: 'POST',
						url: ajaxurl,
						data: {
							action: 'two_factor_set_key',
							user_id: '<?php echo esc_js( $user->ID ); ?>',
							nonce: '<?php echo esc_js( $ajax_nonce ); ?>',
							key : $key
						},
						dataType: 'JSON',
						success: function( response ) {
							$( '.two-factor-gpg-key' ).show();
							$( '.two-factor-gpg-key' ).html('<pre>'+response.data.key+'</pre>');
						}
					} );
				} );
			} )( jQuery );
		</script>
		<?php
	}


	/**
	* Strips the key from the comments
	*
	* @param string $key a public key inputed by the user.
	*/
	public function strip_key($key){
		// Remove first 3 lines
		$storedKey = implode("\n", array_slice(explode("\n", $key), 3));
		// Remove last line
		$storedKey = substr($storedKey, 0, strrpos($storedKey, "\n"));
		return $storedKey;
	}


	/**
	* Checks the validity of a given key
	*
	* @param string $key 
	*
	* @return boolean
	*/
	public function test_key($key){
		try{
			$this->encrypt_token("toto",$key);
			return true;
		}catch(Execption $ex){
			return false;
		}
	}

	/**
	 * Sets a key for the user
	 *
	 * @since 0.1-dev
	 */
	public function ajax_set_key() {
		$user = get_user_by( 'id', sanitize_text_field( $_POST['user_id'] ) );
		check_ajax_referer( 'two-factor-backup-codes-set-key-' . $user->ID, 'nonce' );

		$key = $_POST['key'];

		$storedKey = $this->strip_key($key);

		if($this->test_key($storedKey)){
			// Set public key in DB
			update_user_meta( $user->ID, self::GPG_META_KEY, $storedKey);
			// Send the response.
			wp_send_json_success( array( 'key' => "Public key set succesfully.") );
		}
	}

	/**
	* Generates a random token
	*
	* @param WP_User $user WP_User object of the logged-in user.
	*/
	public function generate_token($user){
        $token = wp_generate_password( 12, true, true);
        $token_hashed = wp_hash_password($token);

        update_user_meta( $user->ID, self::GPG_TOKEN_META_KEY, $token_hashed );
        return $token;
	}

	/**
	* Encryptes given token with a given key
	*
	* @param string $token token to be encrypted
	* @param string $key public key to be used in the encryption
	*
	* @return string 
	*/
	public function encrypt_token($token, $key){
				require_once( TWO_FACTOR_DIR . 'includes/Gpg-php/GPG.php' );

				$key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"."\n\n".$key."\n-----END PGP PUBLIC KEY BLOCK-----";
				$gpg = new GPG();
				$pub_key = new GPG_Public_Key($key);
            	return $gpg->encrypt($pub_key, $token,"");
	}

	/**
	 * Prints the form that prompts the user to authenticate.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 */
	public function authentication_page( $user ) {
		require_once( ABSPATH .  '/wp-admin/includes/template.php' );
		?>
		<p><?php esc_html_e( 'Decrypt the message with the key you have provided, then copy-paste the output here:' ); ?></p><br/>
			
			<?php 
			$key = get_user_meta( $user->ID, self::GPG_META_KEY, true );
			$token = $this->generate_token($user);
			$ecnrypted_token = $this->encrypt_token($token, $key);
			?>


			<textarea cols="33" rows="10"><?php echo $ecnrypted_token; ?></textarea>
		<p>
			<label for="authcode"><?php esc_html_e( 'Verification Code:' ); ?></label>
			<input type="tel" name="two-factor-token" id="authcode" class="input" value="" size="20" />
		</p>
		<?php
		submit_button( __( 'Submit' ) );
	}

	/**
	 * Validates the users input token.
	 *
	 * In this class we just return true.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @return boolean
	 */
	public function validate_authentication( $user ) {
		return $this->validate_code( $user, $_POST['two-factor-token'] );
	}

	/**
	 * Validates a token. @TODO : Add lifespan of a token
	 *
	 * Tokens are single use and are deleted upon a successful validation.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @param int     $token The generated token.
	 * @return boolean
	 */
	public function validate_code( $user, $token ) {
		$token_hashed = get_user_meta( $user->ID, self::GPG_TOKEN_META_KEY, true );

		if($token_hashed == false || $token_hashed ==""){
			return false;
		}else {

			if ( wp_check_password( $token, $token_hashed, $user->ID ) ) {
					$this->delete_code( $user, $token_hashed );
					return true;
				}
			return false;
		}
	}

	/**
	 * Deletes a token.
	 *
	 * @since 0.1-dev
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 * @param string  $token_hashed The hashed the backup code.
	 */
	public function delete_code( $user, $token_hashed ) {
		delete_user_meta($user->ID, self::GPG_TOKEN_META_KEY,$token_hashed);
	}
}
