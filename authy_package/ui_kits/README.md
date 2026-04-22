# Authy UI Kits

Pre-built, production-ready authentication components for modern frontend frameworks.

## 📦 Available Kits

### Svelte 5 (`/svelte`)
- **LoginForm.svelte**: Complete login form with email/password, social login, magic links
- **Features**: 
  - Svelte 5 Runes compatible (`$state`, `$derived`)
  - TypeScript support
  - Customizable via props
  - Built-in error handling
  - Auto-redirect on success
  - CSS variables for theming
  - Accessible (ARIA compliant)

### Vue 3.x (`/vue`)
- **LoginForm.vue**: Complete login form using Composition API
- **Features**:
  - `<script setup>` syntax
  - TypeScript support
  - Reactive state management
  - Form validation
  - Emit events for parent integration
  - Scoped CSS with CSS variables
  - Tailwind CSS ready

### React (`/react`)
- **Components**: LoginForm, SignUpForm, MagicLinkButton, SocialLogin, MFAInput
- **Features**:
  - Hooks-based (useState, useEffect)
  - TypeScript interfaces
  - Controlled components
  - Custom hooks for auth state
  - Styled-components or Tailwind support

## 🎨 Theming

All components use CSS variables for easy customization:

```css
:root {
  --authy-primary: #3b82f6;       /* Primary button color */
  --authy-bg-color: #f3f4f6;      /* Background */
  --authy-text-primary: #111827;  /* Main text */
  --authy-text-secondary: #6b7280; /* Secondary text */
  --authy-border: #d1d5db;        /* Border color */
}
```

## 🚀 Usage Examples

### Svelte 5
```svelte
<script>
  import LoginForm from 'authy-package/ui_kits/svelte/LoginForm.svelte';
  
  function handleSuccess(event) {
    console.log('User logged in:', event.detail.user);
    // Store token, redirect, etc.
  }
</script>

<LoginForm 
  actionUrl="/api/auth/login"
  redirectUrl="/dashboard"
  showSocial={true}
  on:success={handleSuccess}
/>
```

### Vue 3
```vue
<script setup lang="ts">
import LoginForm from 'authy-package/ui_kits/vue/LoginForm.vue';

function handleSuccess({ user, token }: { user: any; token: string }) {
  console.log('Logged in:', user);
  localStorage.setItem('token', token);
}
</script>

<template>
  <LoginForm 
    :actionUrl="'/api/auth/login'"
    :redirectUrl="'/dashboard'"
    :showSocial="true"
    @success="handleSuccess"
  />
</template>
```

### React
```tsx
import { LoginForm } from 'authy-package/ui_kits/react';

function App() {
  const handleSuccess = ({ user, token }) => {
    console.log('Logged in:', user);
  };

  return (
    <LoginForm 
      actionUrl="/api/auth/login"
      redirectUrl="/dashboard"
      showSocial={true}
      onSuccess={handleSuccess}
    />
  );
}
```

## 🛠️ Installation

Components are included in the `authy-package` Python distribution but can be copied directly to your frontend project:

```bash
# Copy Svelte components
cp -r node_modules/authy-package/ui_kits/svelte src/components/auth/

# Copy Vue components
cp -r node_modules/authy-package/ui_kits/vue src/components/auth/

# Copy React components
cp -r node_modules/authy-package/ui_kits/react src/components/auth/
```

Or install via npm (future):
```bash
npm install authy-ui
```

## ✨ Features

- **Zero Configuration**: Works out of the box
- **Accessible**: WCAG 2.1 compliant
- **Responsive**: Mobile-first design
- **Customizable**: Props and CSS variables
- **Type Safe**: Full TypeScript support
- **Framework Agnostic**: Same look across Svelte, Vue, React
- **Production Ready**: Error handling, loading states, validation

## 📝 Component Props

### LoginForm

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `actionUrl` | string | `/api/auth/login` | API endpoint for login |
| `redirectUrl` | string | `/dashboard` | Where to redirect on success |
| `showSocial` | boolean | `true` | Show Google/GitHub buttons |
| `showMagicLink` | boolean | `true` | Show magic link option |
| `forgotPasswordUrl` | string | `/auth/forgot-password` | Link to password reset |
| `signUpUrl` | string | `/auth/signup` | Link to registration |
| `titleLabel` | string | `'Welcome back'` | Form title |
| `submitLabel` | string | `'Sign In'` | Button text |

## 🎯 Events

### Svelte
```svelte
<LoginForm 
  on:success={(e) => console.log(e.detail)}
  on:error={(e) => console.error(e.detail)}
/>
```

### Vue
```vue
<LoginForm 
  @success="handleSuccess"
  @error="handleError"
/>
```

### React
```tsx
<LoginForm 
  onSuccess={({ user, token }) => ...}
  onError={({ message }) => ...}
/>
```

## 🔒 Security

- No sensitive data stored in components
- CSRF protection via backend integration
- Secure token handling (passed to parent, not stored in component)
- Input sanitization
- Rate limiting handled by backend

---

For more information, see the main [README.md](../../README.md).
