<script setup lang="ts">
import { ref, computed } from 'vue';

// Props for customization.
// API location is fully configurable: point `apiBaseUrl` at the auth backend
// origin (default: current origin) and `loginPath` at the login route it
// serves. The request goes to `${apiBaseUrl}${loginPath}`.
interface Props {
  apiBaseUrl?: string;
  loginPath?: string;
  redirectUrl?: string;
  showSocial?: boolean;
  showMagicLink?: boolean;
  magicLinkUrl?: string;
  forgotPasswordUrl?: string;
  signUpUrl?: string;
  titleLabel?: string;
  submitLabel?: string;
}

const props = withDefaults(defineProps<Props>(), {
  apiBaseUrl: '',
  loginPath: '/api/auth/login',
  // Empty string disables auto-redirect; handle the `success` event instead.
  redirectUrl: '',
  // Social buttons navigate to `${apiBaseUrl}/api/auth/social/{provider}` —
  // implement that route on your backend or set `showSocial` to false.
  showSocial: true,
  showMagicLink: true,
  // Optional links render only when a URL is provided, so the component
  // never asserts routes the host app does not implement.
  magicLinkUrl: '',
  forgotPasswordUrl: '',
  signUpUrl: '',
  titleLabel: 'Welcome back',
  submitLabel: 'Sign In'
});

// Emits
const emit = defineEmits<{
  success: [value: { user: unknown; token: string }];
  error: [value: { message: string }];
}>();

// State
const email = ref('');
const password = ref('');
const loading = ref(false);
const error = ref<string | null>(null);
const success = ref(false);

// Computed
const actionUrl = computed(() => `${props.apiBaseUrl}${props.loginPath}`);

const isFormValid = computed(() => {
  return email.value.includes('@') && password.value.length >= 8;
});

// Methods
async function handleSubmit() {
  loading.value = true;
  error.value = null;

  try {
    const response = await fetch(actionUrl.value, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: email.value,
        password: password.value
      })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || 'Login failed');
    }

    success.value = true;
    emit('success', { user: data.user, token: data.access_token });

    // Auto redirect only when explicitly configured.
    if (props.redirectUrl) {
      setTimeout(() => {
        window.location.href = props.redirectUrl;
      }, 500);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Login failed';
    error.value = message;
    emit('error', { message });
  } finally {
    loading.value = false;
  }
}

function handleSocialLogin(provider: 'google' | 'github') {
  window.location.href = `${props.apiBaseUrl}/api/auth/social/${provider}`;
}
</script>

<template>
  <div class="tessera-login-container">
    <div class="tessera-card">
      <h2 class="tessera-title">{{ titleLabel }}</h2>

      <div v-if="success" class="tessera-success">
        <p>{{ redirectUrl ? 'Success! Redirecting...' : 'Success! You are signed in.' }}</p>
      </div>

      <form v-else @submit.prevent="handleSubmit" class="tessera-form">
        <div v-if="error" class="tessera-error">
          {{ error }}
        </div>

        <!-- Email Field -->
        <div class="tessera-field">
          <label for="email">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            required
            placeholder="you@example.com"
            :disabled="loading"
            class="tessera-input"
          />
        </div>

        <!-- Password Field -->
        <div class="tessera-field">
          <div class="tessera-label-row">
            <label for="password">Password</label>
            <a
              v-if="forgotPasswordUrl"
              :href="forgotPasswordUrl"
              class="tessera-link"
            >
              Forgot?
            </a>
          </div>
          <input
            id="password"
            v-model="password"
            type="password"
            required
            placeholder="••••••••"
            :disabled="loading"
            class="tessera-input"
          />
        </div>

        <!-- Submit Button -->
        <button
          type="submit"
          class="tessera-button"
          :disabled="loading || !isFormValid"
        >
          <span v-if="loading" class="tessera-spinner"></span>
          {{ loading ? 'Signing in...' : submitLabel }}
        </button>
      </form>

      <!-- Magic Link Option (renders only when a URL is configured) -->
      <template v-if="showMagicLink && magicLinkUrl && !success">
        <div class="tessera-divider">OR</div>
        <a :href="magicLinkUrl" class="tessera-secondary-button">
          Send me a magic link
        </a>
      </template>

      <!-- Social Login -->
      <div v-if="showSocial && !success" class="tessera-social-grid">
        <button
          type="button"
          class="tessera-social-btn google"
          @click="handleSocialLogin('google')"
        >
          <svg viewBox="0 0 24 24" width="20" height="20">
            <path
              fill="currentColor"
              d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z"
            />
          </svg>
          Google
        </button>
        <button
          type="button"
          class="tessera-social-btn github"
          @click="handleSocialLogin('github')"
        >
          <svg viewBox="0 0 24 24" width="20" height="20">
            <path
              fill="currentColor"
              d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"
            />
          </svg>
          GitHub
        </button>
      </div>

      <!-- Sign Up Link (renders only when a URL is configured) -->
      <p v-if="signUpUrl && !success" class="tessera-footer">
        Don't have an account?
        <a :href="signUpUrl">Sign up</a>
      </p>
    </div>
  </div>
</template>

<style scoped>
.tessera-login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: var(--tessera-bg-color, #f3f4f6);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.tessera-card {
  background: white;
  padding: 2rem;
  border-radius: 12px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 400px;
}

.tessera-title {
  text-align: center;
  margin-bottom: 1.5rem;
  color: var(--tessera-text-primary, #111827);
  font-size: 1.5rem;
  font-weight: 700;
}

.tessera-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.tessera-field label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--tessera-text-secondary, #374151);
}

.tessera-input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--tessera-border, #d1d5db);
  border-radius: 6px;
  font-size: 1rem;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.tessera-input:focus {
  outline: none;
  border-color: var(--tessera-primary, #3b82f6);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.tessera-label-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.tessera-link {
  font-size: 0.75rem;
  color: var(--tessera-primary, #3b82f6);
  text-decoration: none;
}

.tessera-button {
  width: 100%;
  padding: 0.75rem;
  background-color: var(--tessera-primary, #3b82f6);
  color: white;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 0.5rem;
}

.tessera-button:hover:not(:disabled) {
  opacity: 0.9;
}

.tessera-button:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.tessera-error {
  background-color: #fee2e2;
  color: #dc2626;
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.875rem;
  text-align: center;
}

.tessera-success {
  text-align: center;
  color: #059669;
  font-weight: 500;
  padding: 1rem;
}

.tessera-divider {
  text-align: center;
  margin: 1.5rem 0;
  color: var(--tessera-text-secondary, #9ca3af);
  font-size: 0.875rem;
  position: relative;
}

.tessera-secondary-button {
  display: block;
  width: 100%;
  padding: 0.75rem;
  text-align: center;
  background-color: white;
  border: 1px solid var(--tessera-border, #d1d5db);
  border-radius: 6px;
  color: var(--tessera-text-primary, #111827);
  text-decoration: none;
  font-weight: 500;
  transition: background-color 0.2s;
  box-sizing: border-box;
}

.tessera-secondary-button:hover {
  background-color: #f9fafb;
}

.tessera-social-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-top: 1rem;
}

.tessera-social-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background-color: white;
  border: 1px solid var(--tessera-border, #d1d5db);
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
  color: var(--tessera-text-primary, #111827);
}

.tessera-social-btn:hover {
  background-color: #f9fafb;
}

.tessera-footer {
  text-align: center;
  margin-top: 1.5rem;
  font-size: 0.875rem;
  color: var(--tessera-text-secondary, #6b7280);
}

.tessera-footer a {
  color: var(--tessera-primary, #3b82f6);
  text-decoration: none;
  font-weight: 500;
}

.tessera-spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
