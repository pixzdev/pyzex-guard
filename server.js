/**
 * Pyzex Guard — local development entry point.
 * Vercel deployments use api/index.js instead.
 */
import { createApp } from './lib/app.js';
import { APP, isDemoMode, getProviderConfig, getDatabaseUrl } from './lib/config.js';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const app = createApp();

app.listen(port, () => {
  // Startup banner contains configuration STATE only — never secret values.
  const provider = getProviderConfig();
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: 'info',
      msg: `${APP.name} v${APP.version} listening`,
      port,
      demo_mode: isDemoMode(),
      provider_profile: provider.profile,
      provider_configured: provider.configured,
      database_configured: Boolean(getDatabaseUrl()),
    })
  );
});
