# Vue.js 3 + TypeScript Frontend Architecture

## Core Architecture Overview

### Technology Stack

- **Vue.js 3**: Composition API with `<script setup>` syntax
- **TypeScript**: Full type safety throughout the application
- **Vite**: Lightning-fast build tool and dev server
- **Pinia**: Modern state management for Vue 3
- **Vue Router 4**: Official routing solution
- **Axios**: HTTP client with interceptors
- **GraphQL Zeus**: Type-safe GraphQL client generation

### Project Structure

```
frontend/
├── public/
│   ├── favicon.ico
│   └── index.html
├── src/
│   ├── main.ts                 # Application entry point
│   ├── App.vue                 # Root component
│   ├── assets/
│   │   ├── styles/
│   │   │   ├── main.scss       # Global styles
│   │   │   ├── variables.scss  # SCSS variables
│   │   │   └── components/     # Component-specific styles
│   │   ├── images/
│   │   └── fonts/
│   ├── components/
│   │   ├── common/             # Reusable components
│   │   │   ├── BaseButton.vue
│   │   │   ├── BaseInput.vue
│   │   │   ├── BaseModal.vue
│   │   │   └── index.ts        # Component exports
│   │   ├── layout/
│   │   │   ├── AppHeader.vue
│   │   │   ├── AppSidebar.vue
│   │   │   ├── AppFooter.vue
│   │   │   └── AppLayout.vue
│   │   └── feature/            # Feature-specific components
│   │       ├── user/
│   │       │   ├── UserCard.vue
│   │       │   ├── UserForm.vue
│   │       │   └── UserList.vue
│   │       └── auth/
│   │           ├── LoginForm.vue
│   │           └── RegisterForm.vue
│   ├── views/                  # Page components
│   │   ├── HomeView.vue
│   │   ├── AboutView.vue
│   │   ├── auth/
│   │   │   ├── LoginView.vue
│   │   │   └── RegisterView.vue
│   │   └── user/
│   │       ├── UserListView.vue
│   │       ├── UserDetailView.vue
│   │       └── UserEditView.vue
│   ├── stores/                 # Pinia stores
│   │   ├── index.ts
│   │   ├── auth.ts
│   │   ├── user.ts
│   │   └── app.ts
│   ├── composables/            # Vue composables
│   │   ├── useApi.ts
│   │   ├── useAuth.ts
│   │   ├── useNotifications.ts
│   │   └── useValidation.ts
│   ├── services/               # API services
│   │   ├── api/
│   │   │   ├── client.ts       # Axios configuration
│   │   │   ├── interceptors.ts # Request/response interceptors
│   │   │   └── endpoints.ts    # API endpoints
│   │   ├── graphql/
│   │   │   ├── client.ts       # GraphQL client setup
│   │   │   ├── queries/
│   │   │   ├── mutations/
│   │   │   └── generated/      # Generated types
│   │   ├── user.service.ts
│   │   └── auth.service.ts
│   ├── types/                  # TypeScript type definitions
│   │   ├── api.ts
│   │   ├── user.ts
│   │   ├── auth.ts
│   │   └── global.d.ts
│   ├── utils/
│   │   ├── helpers.ts
│   │   ├── constants.ts
│   │   ├── validators.ts
│   │   └── formatters.ts
│   ├── plugins/                # Vue plugins
│   │   ├── i18n.ts
│   │   └── notifications.ts
│   ├── router/
│   │   ├── index.ts
│   │   ├── guards.ts           # Route guards
│   │   └── routes.ts
│   └── tests/
│       ├── __mocks__/
│       ├── unit/
│       ├── integration/
│       └── e2e/
├── cypress/                    # E2E tests
├── docs/                       # Project documentation
├── .env.development
├── .env.production
├── vite.config.ts
├── tsconfig.json
├── package.json
└── README.md
```

## State Management Architecture

### Pinia Store Implementation

```typescript
// stores/auth.ts
import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { User, LoginCredentials, AuthState } from "@/types/auth";
import { authService } from "@/services/auth.service";

export const useAuthStore = defineStore("auth", () => {
  // State
  const user = ref<User | null>(null);
  const token = ref<string | null>(localStorage.getItem("auth_token"));
  const isLoading = ref(false);
  const error = ref<string | null>(null);

  // Getters
  const isAuthenticated = computed(() => !!token.value && !!user.value);
  const userRole = computed(() => user.value?.role || "guest");

  // Actions
  const login = async (credentials: LoginCredentials): Promise<void> => {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await authService.login(credentials);
      token.value = response.token;
      user.value = response.user;
      localStorage.setItem("auth_token", response.token);
    } catch (err) {
      error.value = err instanceof Error ? err.message : "Login failed";
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await authService.logout();
    } finally {
      user.value = null;
      token.value = null;
      localStorage.removeItem("auth_token");
    }
  };

  const fetchUser = async (): Promise<void> => {
    if (!token.value) return;

    try {
      user.value = await authService.getCurrentUser();
    } catch (err) {
      // Token might be invalid, logout user
      await logout();
    }
  };

  return {
    // State
    user: readonly(user),
    token: readonly(token),
    isLoading: readonly(isLoading),
    error: readonly(error),

    // Getters
    isAuthenticated,
    userRole,

    // Actions
    login,
    logout,
    fetchUser,
  };
});
```

### User Store with Optimistic Updates

```typescript
// stores/user.ts
import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { User, CreateUserRequest, UpdateUserRequest } from "@/types/user";
import { userService } from "@/services/user.service";

export const useUserStore = defineStore("user", () => {
  const users = ref<User[]>([]);
  const selectedUser = ref<User | null>(null);
  const isLoading = ref(false);
  const error = ref<string | null>(null);

  const getUserById = computed(() => {
    return (id: number) => users.value.find((user) => user.id === id);
  });

  const fetchUsers = async (): Promise<void> => {
    isLoading.value = true;
    error.value = null;

    try {
      users.value = await userService.getUsers();
    } catch (err) {
      error.value = "Failed to fetch users";
    } finally {
      isLoading.value = false;
    }
  };

  const createUser = async (userData: CreateUserRequest): Promise<User> => {
    const tempUser: User = {
      id: Date.now(), // Temporary ID for optimistic update
      ...userData,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Optimistic update
    users.value.push(tempUser);

    try {
      const newUser = await userService.createUser(userData);
      // Replace temp user with real user
      const index = users.value.findIndex((u) => u.id === tempUser.id);
      if (index !== -1) {
        users.value[index] = newUser;
      }
      return newUser;
    } catch (err) {
      // Rollback optimistic update
      users.value = users.value.filter((u) => u.id !== tempUser.id);
      throw err;
    }
  };

  return {
    users: readonly(users),
    selectedUser: readonly(selectedUser),
    isLoading: readonly(isLoading),
    error: readonly(error),
    getUserById,
    fetchUsers,
    createUser,
  };
});
```

## API Integration Layer

### REST API Service

```typescript
// services/api/client.ts
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import { useAuthStore } from "@/stores/auth";

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL:
        import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1",
      timeout: 10000,
      headers: {
        "Content-Type": "application/json",
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const authStore = useAuthStore();
        if (authStore.token) {
          config.headers.Authorization = `Bearer ${authStore.token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => response,
      async (error) => {
        if (error.response?.status === 401) {
          const authStore = useAuthStore();
          await authStore.logout();
          // Redirect to login page
          window.location.href = "/login";
        }
        return Promise.reject(error);
      }
    );
  }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.get<T>(url, config);
    return response.data;
  }

  async post<T>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const response = await this.client.post<T>(url, data, config);
    return response.data;
  }

  async put<T>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const response = await this.client.put<T>(url, data, config);
    return response.data;
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.client.delete<T>(url, config);
    return response.data;
  }
}

export const apiClient = new ApiClient();
```

### GraphQL Client Setup

```typescript
// services/graphql/client.ts
import { GraphQLClient } from "graphql-request";
import { useAuthStore } from "@/stores/auth";

class GraphQLService {
  private client: GraphQLClient;

  constructor() {
    this.client = new GraphQLClient(
      import.meta.env.VITE_GRAPHQL_ENDPOINT || "http://localhost:8000/graphql",
      {
        headers: this.getHeaders(),
      }
    );
  }

  private getHeaders() {
    const authStore = useAuthStore();
    return {
      ...(authStore.token && { Authorization: `Bearer ${authStore.token}` }),
    };
  }

  async request<T>(query: string, variables?: any): Promise<T> {
    this.client.setHeaders(this.getHeaders());
    return this.client.request<T>(query, variables);
  }
}

export const graphqlClient = new GraphQLService();
```

## Component Architecture

### Base Component System

```vue
<!-- components/common/BaseButton.vue -->
<template>
  <button
    :class="buttonClasses"
    :disabled="disabled || loading"
    @click="handleClick"
  >
    <slot v-if="!loading" />
    <span v-else class="loading-spinner" />
  </button>
</template>

<script setup lang="ts">
import { computed } from "vue";

interface Props {
  variant?: "primary" | "secondary" | "danger";
  size?: "sm" | "md" | "lg";
  disabled?: boolean;
  loading?: boolean;
}

interface Emits {
  click: [];
}

const props = withDefaults(defineProps<Props>(), {
  variant: "primary",
  size: "md",
  disabled: false,
  loading: false,
});

const emit = defineEmits<Emits>();

const buttonClasses = computed(() => [
  "base-button",
  `base-button--${props.variant}`,
  `base-button--${props.size}`,
  {
    "base-button--disabled": props.disabled,
    "base-button--loading": props.loading,
  },
]);

const handleClick = () => {
  if (!props.disabled && !props.loading) {
    emit("click");
  }
};
</script>

<style scoped lang="scss">
.base-button {
  @apply px-4 py-2 rounded-md font-medium transition-colors duration-200;

  &--primary {
    @apply bg-blue-600 text-white hover:bg-blue-700;
  }

  &--secondary {
    @apply bg-gray-200 text-gray-900 hover:bg-gray-300;
  }

  &--danger {
    @apply bg-red-600 text-white hover:bg-red-700;
  }

  &--sm {
    @apply px-3 py-1 text-sm;
  }

  &--lg {
    @apply px-6 py-3 text-lg;
  }

  &--disabled {
    @apply opacity-50 cursor-not-allowed;
  }

  &--loading {
    @apply cursor-wait;
  }
}

.loading-spinner {
  @apply inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin;
}
</style>
```

### Composables for Reusable Logic

```typescript
// composables/useApi.ts
import { ref, Ref } from "vue";

interface ApiState<T> {
  data: Ref<T | null>;
  loading: Ref<boolean>;
  error: Ref<string | null>;
}

export function useApi<T>() {
  const data = ref<T | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const execute = async (apiCall: () => Promise<T>): Promise<T | null> => {
    loading.value = true;
    error.value = null;

    try {
      const result = await apiCall();
      data.value = result;
      return result;
    } catch (err) {
      error.value = err instanceof Error ? err.message : "An error occurred";
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const reset = () => {
    data.value = null;
    error.value = null;
    loading.value = false;
  };

  return {
    data: readonly(data),
    loading: readonly(loading),
    error: readonly(error),
    execute,
    reset,
  };
}
```

```typescript
// composables/useValidation.ts
import { ref, computed, Ref } from "vue";

type ValidationRule<T> = (value: T) => string | null;

interface ValidationResult {
  isValid: Ref<boolean>;
  errors: Ref<string[]>;
  validate: () => boolean;
  reset: () => void;
}

export function useValidation<T>(
  value: Ref<T>,
  rules: ValidationRule<T>[]
): ValidationResult {
  const errors = ref<string[]>([]);

  const isValid = computed(() => errors.value.length === 0);

  const validate = (): boolean => {
    errors.value = [];

    for (const rule of rules) {
      const result = rule(value.value);
      if (result) {
        errors.value.push(result);
      }
    }

    return isValid.value;
  };

  const reset = () => {
    errors.value = [];
  };

  return {
    isValid: readonly(isValid),
    errors: readonly(errors),
    validate,
    reset,
  };
}

// Validation rules
export const validationRules = {
  required: <T>(value: T): string | null => {
    if (!value || (typeof value === "string" && !value.trim())) {
      return "This field is required";
    }
    return null;
  },

  email: (value: string): string | null => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (value && !emailRegex.test(value)) {
      return "Please enter a valid email address";
    }
    return null;
  },

  minLength:
    (min: number) =>
    (value: string): string | null => {
      if (value && value.length < min) {
        return `Must be at least ${min} characters long`;
      }
      return null;
    },
};
```

## Routing Architecture

### Router Configuration

```typescript
// router/index.ts
import { createRouter, createWebHistory } from "vue-router";
import { setupRouterGuards } from "./guards";
import { routes } from "./routes";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition;
    }
    return { top: 0 };
  },
});

setupRouterGuards(router);

export default router;
```

```typescript
// router/guards.ts
import type { Router } from "vue-router";
import { useAuthStore } from "@/stores/auth";

export function setupRouterGuards(router: Router) {
  router.beforeEach(async (to, from, next) => {
    const authStore = useAuthStore();

    // Check if route requires authentication
    if (to.meta.requiresAuth && !authStore.isAuthenticated) {
      next({ name: "Login", query: { redirect: to.fullPath } });
      return;
    }

    // Check role-based access
    if (to.meta.roles && authStore.user) {
      const hasRequiredRole = to.meta.roles.includes(authStore.userRole);
      if (!hasRequiredRole) {
        next({ name: "Forbidden" });
        return;
      }
    }

    next();
  });
}
```

## Testing Strategy

### Unit Testing Setup

```typescript
// tests/unit/components/BaseButton.test.ts
import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import BaseButton from "@/components/common/BaseButton.vue";

describe("BaseButton", () => {
  it("renders correctly with default props", () => {
    const wrapper = mount(BaseButton, {
      slots: {
        default: "Click me",
      },
    });

    expect(wrapper.text()).toBe("Click me");
    expect(wrapper.classes()).toContain("base-button--primary");
    expect(wrapper.classes()).toContain("base-button--md");
  });

  it("emits click event when clicked", async () => {
    const wrapper = mount(BaseButton);

    await wrapper.trigger("click");

    expect(wrapper.emitted("click")).toHaveLength(1);
  });

  it("does not emit click when disabled", async () => {
    const wrapper = mount(BaseButton, {
      props: { disabled: true },
    });

    await wrapper.trigger("click");

    expect(wrapper.emitted("click")).toBeUndefined();
  });
});
```

### Integration Testing

```typescript
// tests/integration/stores/auth.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { setActivePinia, createPinia } from "pinia";
import { useAuthStore } from "@/stores/auth";
import { authService } from "@/services/auth.service";

vi.mock("@/services/auth.service");

describe("Auth Store", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it("should login successfully", async () => {
    const authStore = useAuthStore();
    const mockResponse = {
      token: "test-token",
      user: { id: 1, email: "test@example.com", role: "user" },
    };

    vi.mocked(authService.login).mockResolvedValue(mockResponse);

    await authStore.login({ email: "test@example.com", password: "password" });

    expect(authStore.isAuthenticated).toBe(true);
    expect(authStore.user?.email).toBe("test@example.com");
  });
});
```

## Build Configuration

### Vite Configuration

```typescript
// vite.config.ts
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "path";

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: `@import "@/assets/styles/variables.scss";`,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["vue", "vue-router", "pinia"],
          ui: ["@headlessui/vue", "@heroicons/vue"],
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
```

## Performance Optimization

### Lazy Loading & Code Splitting

```typescript
// router/routes.ts
import type { RouteRecordRaw } from "vue-router";

export const routes: RouteRecordRaw[] = [
  {
    path: "/",
    name: "Home",
    component: () => import("@/views/HomeView.vue"),
  },
  {
    path: "/users",
    name: "Users",
    component: () => import("@/views/user/UserListView.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/admin",
    name: "Admin",
    component: () => import("@/views/admin/AdminView.vue"),
    meta: { requiresAuth: true, roles: ["admin"] },
  },
];
```

### Caching Strategy

```typescript
// composables/useCache.ts
import { ref, Ref } from "vue";

interface CacheOptions {
  ttl?: number; // Time to live in milliseconds
}

class CacheManager {
  private cache = new Map<
    string,
    { data: any; timestamp: number; ttl: number }
  >();

  set(key: string, data: any, options: CacheOptions = {}): void {
    const ttl = options.ttl || 5 * 60 * 1000; // Default 5 minutes
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
    });
  }

  get<T>(key: string): T | null {
    const item = this.cache.get(key);
    if (!item) return null;

    if (Date.now() - item.timestamp > item.ttl) {
      this.cache.delete(key);
      return null;
    }

    return item.data;
  }

  clear(): void {
    this.cache.clear();
  }
}

export const cacheManager = new CacheManager();

export function useCache() {
  return cacheManager;
}
```

## Development Tooling

### TypeScript Configuration

```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "module": "ESNext",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "preserve",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*.ts", "src/**/*.d.ts", "src/**/*.tsx", "src/**/*.vue"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

This architecture provides a robust, scalable, and maintainable frontend foundation that integrates seamlessly with your Python backend, offering excellent developer experience and optimal performance.
