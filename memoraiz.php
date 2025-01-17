<?php
/**
 * Plugin Name: MemorAIz
 * Description: Extend popular LMS like LearnDash with AI functionalities
 * Version: 0.1.0
 * Author: MemorAIz S.R.L.
 */

if (!defined('ABSPATH')) {
  exit; // Exit if accessed directly.
}

class MemoraizPlugin {
  private $option_name = 'memoraiz_settings';
  private $cookie_name = 'memoraiz_token';
  private $cookie_expiry = 3600; // 1 hour
  private $current_token = null;


  public function __construct() {
    // Add init hook for early cookie handling
    add_action('init', array($this, 'handle_auth_token'), 5);
  }

  /**
   * Encrypt data before storing it.
   *
   * @param string $data Data to encrypt.
   * @return string Encrypted data.
   */
  private function encrypt($data) {
    if (empty($data)) {
      return false;
    }

		$encryption_key = wp_salt('auth');
		$iv = openssl_random_pseudo_bytes(16);
		$encrypted = openssl_encrypt(
      $data,
      'AES-256-CBC',
      substr($encryption_key, 0, 32),
      0,
      $iv
    );

		if ($encrypted === false) {
      return false;
    }

		return base64_encode($iv . $encrypted);
  }

  /**
   * Decrypt data after retrieving it.
   *
   * @param string $data Encrypted data to decrypt.
   * @return string Decrypted data.
   */
  private function decrypt($data) {
		if (empty($data)) {
      return false;
    }

    $data = base64_decode($data);

    if ($data === false) {
      return false;
    }

		$encryption_key = wp_salt('auth');
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);

		return openssl_decrypt(
      $encrypted,
      'AES-256-CBC',
      substr($encryption_key, 0, 32),
      0,
      $iv
    );
  }

  /**
   * Generate a JWT signed with the private key using ES256 algorithm.
   *
   * @param array $payload The payload for the JWT.
   * @return string|null Signed JWT or null if signing fails.
   */
  private function generate_jwt($payload) {
    $settings = $this->get_settings();

		if (empty($settings['auth_key'])) {
      error_log('MemorAIz auth key not set.');
      return null;
    }

		// Check if the key starts with the PEM header
		if (!str_contains($settings['auth_key'], '-----BEGIN')) {
			error_log('Invalid private key format: missing PEM header');
			return null;
		}

		try {
      $private_key = openssl_pkey_get_private($settings['auth_key']);
      if ($private_key === false) {
        error_log('Invalid private key format');
        return null;
      }

      $header = $this->base64_url_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT']));
      $payload = $this->base64_url_encode(json_encode($payload));
      $data = $header . '.' . $payload;

      $signature = '';
      if (!openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA256)) {
        error_log('Failed to sign JWT: ' . openssl_error_string());
        return null;
      }

      openssl_free_key($private_key);

      // Convert the DER-encoded signature to raw R and S format
      $der = $signature;
      $len = strlen($der);
      $r = '';
      $s = '';

      // Extract R and S from the DER-encoded signature
      $rStart = 4;
      $rLength = ord($der[$rStart - 1]);
      $r = substr($der, $rStart, $rLength);

      $sStart = $rStart + $rLength + 2;
      $sLength = ord($der[$sStart - 1]);
      $s = substr($der, $sStart, $sLength);

      // Ensure R and S are 32 bytes long (pad with leading zeros if necessary)
      $r = str_pad($r, 32, "\0", STR_PAD_LEFT);
      $s = str_pad($s, 32, "\0", STR_PAD_LEFT);

      // Concatenate R and S
      $rawSignature = $r . $s;

      // Combine the JWT parts
      return $data . '.' . $this->base64_url_encode($rawSignature);
    } catch (Exception $e) {
      error_log('JWT generation error: ' . $e->getMessage());
      return null;
    }
  }

	/**
   * Handle authentication token generation and cookie setting.
   * Called early in the WordPress lifecycle.
   */
  public function handle_auth_token() {
    $user = wp_get_current_user();
    if (!$user || !$user->ID) {
      return;
    }

    // Check for existing cookie
    $encrypted_token = isset($_COOKIE[$this->cookie_name]) ? $_COOKIE[$this->cookie_name] : '';
    if ($encrypted_token) {
      $token = $this->decrypt($encrypted_token);
      if ($token) {
        $this->current_token = $token;
        return;
      }
    }

    // Generate new token if needed
    $expiration = time() + $this->cookie_expiry;
    $token = $this->generate_jwt([
      'iss' => get_site_url(),
      'sub' => $user->ID,
      'iat' => time(),
      'exp' => $expiration,
      'name' => $user->display_name,
    ]);

    if (!$token) {
      return;
    }

    // Encrypt token for cookie storage
    $encrypted_token = $this->encrypt($token);
    if (!$encrypted_token) {
      return;
    }

    // Set secure cookie
    setcookie(
      $this->cookie_name,
      $encrypted_token,
      [
        'expires' => $expiration,
        'path' => COOKIEPATH,
        'domain' => COOKIE_DOMAIN,
        'secure' => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax'
      ]
    );

    $this->current_token = $token;
  }

	/**
   * Save plugin settings securely.
   *
   * @param array $settings Settings to save.
   */
  public function save_settings($settings) {
    if (isset($settings['auth_key'])) {
      $settings['auth_key'] = $this->encrypt($settings['auth_key']);
    }
    update_option($this->option_name, $settings);
  }

  /**
   * Retrieve plugin settings securely.
   *
   * @return array Plugin settings.
   */
  public function get_settings() {
    $settings = get_option($this->option_name, []);

    if (isset($settings['auth_key'])) {
      $settings['auth_key'] = $this->decrypt($settings['auth_key']);
    }

    return $settings;
  }

  private function base64_url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

	/**
   * Add styles to the frontend
   */
  public function enqueue_styles() {
    $frames_repo = '@memoraiz/frames';
    $frames_version = isset($settings['frames_version']) ? '@'.$settings['frames_version'] : '';
    $frames_css_url = esc_url("https://cdn.jsdelivr.net/npm/{$frames_repo}{$frames_version}/dist/style.css");

    // Register and enqueue the external CSS file
		wp_enqueue_style(
			'memoraiz-style',
			$frames_css_url,
			array(),
			null // Version (optional; use null for no version)
		);
  }

  /**
   * Add a settings page for managing the private key.
   */
  public function add_settings_page() {
    add_options_page(
      'MemorAIz Settings',
      'MemorAIz',
      'manage_options',
      'memoraiz',
      [$this, 'render_settings_page']
    );
  }

  /**
   * Render the settings page.
   */
  public function render_settings_page() {
    $settings = $this->get_settings();

    if (!empty($_POST) && check_admin_referer('save_memoraiz_settings', 'memoraiz_nonce')) {
			$new_settings = $settings; // Start with existing settings

			// Only update auth_key if a new one is provided
      if (!empty($_POST['auth_key'])) {
				$auth_key = str_replace(["\r\n", "\r"], "\n", $_POST['auth_key']);
        $new_settings['auth_key'] = sanitize_textarea_field($auth_key);
      }

			// Update other settings
      $new_settings['frames_version'] = sanitize_text_field($_POST['frames_version'] ?? '');
      $new_settings['theme_id'] = sanitize_text_field($_POST['theme_id'] ?? '');
      $new_settings['custom_icon'] = esc_url_raw($_POST['custom_icon'] ?? '');

      $this->save_settings($new_settings);
      echo '<div class="updated"><p>Settings saved successfully.</p></div>';

      // Refresh settings after save
      $settings = $this->get_settings();
    }

    $auth_key_display = isset($settings['auth_key']) ? '***** (Hidden for security)' : 'Not Set';
    $frames_version = isset($settings['frames_version']) ? esc_attr($settings['frames_version']) : '';
    $theme_id = isset($settings['theme_id']) ? esc_attr($settings['theme_id']) : '';
    $custom_icon = isset($settings['custom_icon']) ? esc_url($settings['custom_icon']) : '';

    ?>
    <div class="wrap">
        <h1>MemorAIz Settings</h1>
        <form method="post" action="">
            <?php wp_nonce_field('save_memoraiz_settings', 'memoraiz_nonce'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="auth_key">Auth Key</label>
                    </th>
                    <td>
                        <textarea name="auth_key" id="auth_key" class="large-text" rows="4" placeholder="Enter new private key (leave empty to keep existing)"><?php echo ''; ?></textarea>
                        <p class="description">Current Key Status: <?php echo esc_html($auth_key_display); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="frames_version">Frames Version</label>
                    </th>
                    <td>
                        <input type="text" name="frames_version" id="frames_version" value="<?php echo $frames_version; ?>" class="regular-text">
                        <p class="description">Enter the MemorAIz Frame package version (e.g., 0.0.7)</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="theme_id">Theme ID</label>
                    </th>
                    <td>
                        <select name="theme_id" id="theme_id">
                            <option value="default" <?php selected($theme_id, 'default'); ?>>Default</option>
                            <option value="orange" <?php selected($theme_id, 'orange'); ?>>Orange</option>
                        </select>
                        <p class="description">Select your preferred theme</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="custom_icon">Custom popover icon</label>
                    </th>
                    <td>
                        <input type="text" name="custom_icon" id="custom_icon" value="<?php echo $custom_icon; ?>" class="regular-text">
                        <p class="description">Enter the URL to an icon</p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Save Settings'); ?>
        </form>
    </div>
    <?php
  }

  /**
   * Dynamically render a script tag in the footer based on settings.
   */
  public function render_footer_script() {
    $user = wp_get_current_user();

    if (!$user || !$user->ID) {
        return;
    }

    if (!$this->current_token) {
        return;
    }

    $settings = $this->get_settings();

    $frames_repo = '@memoraiz/frames';
    $frames_version = isset($settings['frames_version']) ? '@'.$settings['frames_version'] : '';
    $frames_url = esc_url("https://cdn.jsdelivr.net/npm/{$frames_repo}{$frames_version}/dist/index.js");

    $theme_id = isset($settings['theme_id']) && !empty($settings['theme_id']) ? esc_js($settings['theme_id']) : '';

		$custom_icon = isset($settings['custom_icon']) && !empty($settings['custom_icon']) ? esc_js($settings['custom_icon']) : '';

    ?>
    <script id="memo-script" type="module">
      try {
        import ('<?php echo $frames_url; ?>').then(() => {
          console.log('MemorAIz frames loaded successfully');

          window.memoraiz.setSession('<?php echo esc_js($this->current_token); ?>', {
            id: '<?php echo esc_js($user->ID); ?>',
            displayName: '<?php echo esc_js($user->display_name); ?>',
          });

          <?php if (!empty($theme_id)) : ?>
          window.memoraiz.setTheme({ id: '<?php echo $theme_id; ?>' });
          <?php endif; ?>

          const frameConfig = {};
          <?php if (!empty($custom_icon)) : ?>
          frameConfig.triggerIconUrl = '<?php echo $custom_icon; ?>';
          <?php endif; ?>

          const frame = window.memoraiz.mount('learndash', frameConfig);
        }).catch(error => {
          console.error('Failed to load MemorAIz frames:', error);
        });
      } catch (error) {
        console.error('Error initializing MemorAIz:', error);
      }
    </script>
    <?php
  }
}

// Initialize the plugin.
$memoraiz_plugin = new MemoraizPlugin();

// Add admin menu and settings page
add_action('admin_menu', [$memoraiz_plugin, 'add_settings_page']);

// Add frontend styles
add_action('wp_enqueue_scripts',[$memoraiz_plugin, 'enqueue_styles']);

// Add frontend script
add_action('wp_footer', [$memoraiz_plugin, 'render_footer_script']);
