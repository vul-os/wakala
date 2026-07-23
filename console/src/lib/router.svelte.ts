// A minimal hash router — six known routes, no external dependency.

export type Route = 'overview' | 'descriptor' | 'tariff' | 'billing' | 'keys' | 'conformance';

const ROUTES: Route[] = ['overview', 'descriptor', 'tariff', 'billing', 'keys', 'conformance'];

function parse(hash: string): Route {
  const clean = hash.replace(/^#\/?/, '') as Route;
  return ROUTES.includes(clean) ? clean : 'overview';
}

class Router {
  current = $state<Route>(parse(typeof location !== 'undefined' ? location.hash : ''));

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('hashchange', () => {
        this.current = parse(location.hash);
      });
    }
  }

  go(route: Route) {
    location.hash = `/${route}`;
    this.current = route;
  }
}

export const router = new Router();
