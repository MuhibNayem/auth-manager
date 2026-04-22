<script lang="ts">
	import { onMount } from 'svelte';
	import { createEventDispatcher } from 'svelte';

	// Svelte 5 Runes (if using Svelte 5 preview/compiler)
	// let email = $state('');
	// let password = $state('');
	// let loading = $state(false);
	// let error = $state<string | null>(null);

	// Standard Svelte 4/5 compatible syntax
	let email = '';
	let password = '';
	let loading = false;
	let error: string | null = null;
	let success = false;

	const dispatch = createEventDispatcher<{
		success: { user: any; token: string };
		error: { message: string };
	}>();

	export let actionUrl = '/api/auth/login';
	export let redirectUrl = '/dashboard';
	export let showSocial = true;
	export let showMagicLink = true;
	export let forgotPasswordUrl = '/auth/forgot-password';
	export let signUpUrl = '/auth/signup';

	// Customizable labels
	export let titleLabel = 'Welcome back';
	export let submitLabel = 'Sign In';

	async function handleSubmit(e: Event) {
		e.preventDefault();
		loading = true;
		error = null;

		try {
			const res = await fetch(actionUrl, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email, password })
			});

			const data = await res.json();

			if (!res.ok) {
				throw new Error(data.detail || 'Login failed');
			}

			success = true;
			dispatch('success', { user: data.user, token: data.access_token });
			
			// Auto redirect if URL provided
			if (redirectUrl) {
				setTimeout(() => {
					window.location.href = redirectUrl;
				}, 500);
			}
		} catch (err: any) {
			error = err.message;
			dispatch('error', { message: error });
		} finally {
			loading = false;
		}
	}
</script>

<div class="authy-login-container">
	<div class="authy-card">
		<h2 class="authy-title">{titleLabel}</h2>

		{#if success}
			<div class="authy-success">
				<p>Success! Redirecting...</p>
			</div>
		{:else}
			<form on:submit={handleSubmit} class="authy-form">
				{#if error}
					<div class="authy-error">{error}</div>
				{/if}

				<div class="authy-field">
					<label for="email">Email</label>
					<input 
						type="email" 
						id="email" 
						bind:value={email} 
						required 
						placeholder="you@example.com"
						disabled={loading}
					/>
				</div>

				<div class="authy-field">
					<div class="authy-label-row">
						<label for="password">Password</label>
						{#if forgotPasswordUrl}
							<a href={forgotPasswordUrl} class="authy-link">Forgot?</a>
						{/if}
					</div>
					<input 
						type="password" 
						id="password" 
						bind:value={password} 
						required 
						placeholder="••••••••"
						disabled={loading}
					/>
				</div>

				<button type="submit" class="authy-button" disabled={loading}>
					{#if loading}
						<span class="authy-spinner"></span> Signing in...
					{:else}
						{submitLabel}
					{/if}
				</button>
			</form>

			{#if showMagicLink}
				<div class="authy-divider">OR</div>
				<a href="/auth/magic" class="authy-secondary-button">
					Send me a magic link
				</a>
			{/if}

			{#if showSocial}
				<div class="authy-social-grid">
					<button type="button" class="authy-social-btn google">
						<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032s2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.503,2.988,15.139,2,12.545,2C7.021,2,2.543,6.477,2.543,12s4.478,10,10.002,10c8.396,0,10.249-7.85,9.426-11.748L12.545,10.239z"/></svg>
						Google
					</button>
					<button type="button" class="authy-social-btn github">
						<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
						GitHub
					</button>
				</div>
			{/if}

			<p class="authy-footer">
				Don't have an account? <a href={signUpUrl}>Sign up</a>
			</p>
		{/if}
	</div>
</div>

<style>
	.authy-login-container {
		display: flex;
		justify-content: center;
		align-items: center;
		min-height: 100vh;
		background-color: var(--authy-bg-color, #f3f4f6);
		font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
	}
	.authy-card {
		background: white;
		padding: 2rem;
		border-radius: 12px;
		box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
		width: 100%;
		max-width: 400px;
	}
	.authy-title {
		text-align: center;
		margin-bottom: 1.5rem;
		color: var(--authy-text-primary, #111827);
		font-size: 1.5rem;
		font-weight: 700;
	}
	.authy-form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.authy-field label {
		display: block;
		margin-bottom: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: var(--authy-text-secondary, #374151);
	}
	.authy-field input {
		width: 100%;
		padding: 0.75rem;
		border: 1px solid var(--authy-border, #d1d5db);
		border-radius: 6px;
		font-size: 1rem;
		transition: border-color 0.2s;
		box-sizing: border-box;
	}
	.authy-field input:focus {
		outline: none;
		border-color: var(--authy-primary, #3b82f6);
		box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
	}
	.authy-label-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.authy-link {
		font-size: 0.75rem;
		color: var(--authy-primary, #3b82f6);
		text-decoration: none;
	}
	.authy-button {
		width: 100%;
		padding: 0.75rem;
		background-color: var(--authy-primary, #3b82f6);
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
	.authy-button:hover:not(:disabled) {
		opacity: 0.9;
	}
	.authy-button:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}
	.authy-error {
		background-color: #fee2e2;
		color: #dc2626;
		padding: 0.75rem;
		border-radius: 6px;
		font-size: 0.875rem;
		text-align: center;
	}
	.authy-success {
		text-align: center;
		color: #059669;
		font-weight: 500;
	}
	.authy-divider {
		text-align: center;
		margin: 1.5rem 0;
		color: var(--authy-text-secondary, #9ca3af);
		font-size: 0.875rem;
		position: relative;
	}
	.authy-secondary-button {
		display: block;
		width: 100%;
		padding: 0.75rem;
		text-align: center;
		background-color: white;
		border: 1px solid var(--authy-border, #d1d5db);
		border-radius: 6px;
		color: var(--authy-text-primary, #111827);
		text-decoration: none;
		font-weight: 500;
		transition: background-color 0.2s;
		box-sizing: border-box;
	}
	.authy-secondary-button:hover {
		background-color: #f9fafb;
	}
	.authy-social-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
		margin-top: 1rem;
	}
	.authy-social-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 0.75rem;
		background-color: white;
		border: 1px solid var(--authy-border, #d1d5db);
		border-radius: 6px;
		font-weight: 500;
		cursor: pointer;
		transition: background-color 0.2s;
		color: var(--authy-text-primary, #111827);
	}
	.authy-social-btn:hover {
		background-color: #f9fafb;
	}
	.authy-footer {
		text-align: center;
		margin-top: 1.5rem;
		font-size: 0.875rem;
		color: var(--authy-text-secondary, #6b7280);
	}
	.authy-footer a {
		color: var(--authy-primary, #3b82f6);
		text-decoration: none;
		font-weight: 500;
	}
	.authy-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid rgba(255,255,255,0.3);
		border-radius: 50%;
		border-top-color: white;
		animation: spin 0.8s linear infinite;
	}
	@keyframes spin {
		to { transform: rotate(360deg); }
	}
</style>
