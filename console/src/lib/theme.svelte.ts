// Theme state: 'system' respects prefers-color-scheme (the default); 'light'/'dark' pin an
// explicit choice via the [data-theme] override in app.css. Persisted so a reload keeps the
// operator's pick.

export type ThemeChoice = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'wakala:theme';

function readInitial(): ThemeChoice {
  if (typeof localStorage === 'undefined') return 'system';
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored === 'light' || stored === 'dark' ? stored : 'system';
}

class ThemeStore {
  choice = $state<ThemeChoice>(readInitial());

  constructor() {
    $effect.root(() => {
      $effect(() => {
        const root = document.documentElement;
        if (this.choice === 'system') {
          root.removeAttribute('data-theme');
        } else {
          root.setAttribute('data-theme', this.choice);
        }
        try {
          localStorage.setItem(STORAGE_KEY, this.choice);
        } catch {
          /* ignore (private mode / disabled storage) */
        }
      });
    });
  }

  toggle() {
    const effective = this.resolved();
    this.choice = effective === 'dark' ? 'light' : 'dark';
  }

  resolved(): 'light' | 'dark' {
    if (this.choice !== 'system') return this.choice;
    if (typeof matchMedia === 'undefined') return 'light';
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
}

export const theme = new ThemeStore();
