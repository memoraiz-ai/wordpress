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
    private $session_name = 'memoraiz_session';

    /**
     * Encrypt data before storing it.
     *
     * @param string $data Data to encrypt.
     * @return string Encrypted data.
     */
    private function encrypt($data) {
        $encryption_key = wp_salt(); // Use WordPress salt for encryption.
        return base64_encode(openssl_encrypt($data, 'AES-256-CBC', $encryption_key, 0, substr($encryption_key, 0, 16)));
    }

    /**
     * Decrypt data after retrieving it.
     *
     * @param string $data Encrypted data to decrypt.
     * @return string Decrypted data.
     */
    private function decrypt($data) {
        $encryption_key = wp_salt(); // Use WordPress salt for decryption.
        return openssl_decrypt(base64_decode($data), 'AES-256-CBC', $encryption_key, 0, substr($encryption_key, 0, 16));
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

        $header = $this->base64_url_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT']));
        $payload = $this->base64_url_encode(json_encode($payload));
        $data = $header . '.' . $payload;

        $auth_key = $settings['auth_key'];
        $signature = '';
        if (!openssl_sign($data, $signature, $auth_key, OPENSSL_ALGO_SHA256)) {
            error_log('Failed to sign JWT.');
            return null;
        }

        return $data . '.' . $this->base64_url_encode($signature);
    }

    private function base64_url_encode($data) {
      return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function get_session_auth_token() {
      $user = wp_get_current_user();

      if (!$user) {
        return null;
      }

      $auth_token = $_SESSION[$this->session_name] ?? null;
      $auth_token_exp = $_SESSION[$this->session_name.'_exp'] ?? 0;

      if ($auth_token && $auth_token_exp >= time() - 60) {
        return $auth_token;
      }

      $auth_token_exp = time() + 3600;
      $auth_token = $this->generate_jwt([
          'iss' => get_site_url(), // Issuer: your site URL.
          'sub' => get_current_user_id(), // Subject: logged-in user ID.
          'iat' => time(), // Issued at: current time.
          'exp' => $auth_token_exp, // Expiration: 1 hour from now.
          'name' => $user->display_name,  // User information
      ]);

      $_SESSION[$this->session_name] = $auth_token;
      $_SESSION[$this->session_name.'_exp'] = $auth_token_exp;

      return $auth_token;
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

        if (isset($_POST[$this->option_name]) && check_admin_referer('save_memoraiz_settings', 'memoraiz_nonce')) {
            $new_settings = [
                'auth_key' => sanitize_text_field($_POST['auth_key']),
                'frames_version' => sanitize_text_field($_POST['frames_version']),
                'theme_id' => sanitize_text_field($_POST['theme_id']),
                'custom_icon' => sanitize_text_field($_POST['custom_icon']),
            ];

            $this->save_settings($new_settings);
            echo '<div class="updated"><p>Settings saved successfully.</p></div>';
        }

        $auth_key_display = isset($settings['auth_key']) ? '***** (Hidden for security)' : 'Not Set';
        $frames_version = isset($settings['frames_version']) ? $settings['frames_version'] : '';
        $theme_id = isset($settings['theme_id']) ? $settings['theme_id'] : '';
        $custom_icon = isset($settings['custom_icon']) ? $settings['custom_icon'] : '';

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
                            <input type="text" name="auth_key" id="auth_key" value="" class="regular-text"required>
                            <p class="description">Current Key: <?php echo esc_html($auth_key_display); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="frames_version">Frames Version</label>
                        </th>
                        <td>
                            <input type="text" name="frames_version" id="frames_version" value="<?php echo esc_attr($frames_version); ?>" class="regular-text" >
                            <p class="description">Enter the MemorAIz Frame package version (e.g., 0.0.7).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="theme_id">Theme ID</label>
                        </th>
                        <td>
                            <select name="theme_id" id="theme_id" value="<?php echo esc_attr($theme_id); ?>">
                              <option value="">Default</option>
                              <option value="orange">Orange</option>
                            </select>
                            <p class="description">Select your preferred theme</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="custom_icon">Custom popover icon</label>
                        </th>
                        <td>
                            <input type="text" name="custom_icon" id="custom_icon" value="<?php echo esc_attr($custom_icon); ?>" class="regular-text">
                            <p class="description">Enter the url to an icon</p>
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

        if (!$user) {
          return null;
        }

        // generate the access token for the current user
        $access_token = esc_js($this->get_session_auth_token());

        if (!$access_token) {
          return null;
        }

        $settings = $this->get_settings();

        $frames_repo = '@memoraiz/frames';
        $frames_version = isset($settings['frames_version']) ? '@'.$settings['frames_version'] : '';
        $frames_url = esc_url("https://cdn.jsdelivr.net/npm/{$frames_repo}{$frames_version}/dist/index.js");

        $theme_id = isset($settings['theme_id']) ? esc_js($settings['theme_id']) : 'orange';

        ?>
        <script type="module">
            import '<?php echo $frames_url; ?>';

            console.log('Configuring mock environment...');

            window.memoraiz.setSession('<?php echo $access_token; ?>', {
              id: '<?php echo esc_js($user->ID); ?>',
              displayName: '<?php echo esc_js($user->display_name); ?>',
            });

            window.memoraiz.setTheme({ id: '<?php echo $theme_id; ?>' });

            const frame = window.memoraiz.mount('learndash', {
              // triggerIconUrl: mockCustomIcon,
            });
        </script>
        <?php
    }
}

// Initialize the plugin.
$secure_api_plugin = new MemoraizPlugin();

// Render the admin menu and settings page
add_action('admin_menu', [$secure_api_plugin, 'add_settings_page']);

// Hook the script rendering function into the wp_footer action.
add_action('wp_footer', [$secure_api_plugin, 'render_footer_script']);
