/**
 * Pyzex Guard — local development entry point.
 * Vercel deployments use api/index.js instead.
 */
import { createApp } from './lib/app.js';
import { APP } from './lib/config.js';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const app = createApp();

app.listen(port, () => {
  // Startup banner contains configuration STATE only — never secret values.
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: 'info',
      msg: `${APP.name} v${APP.version} listening`,
      port,
      demo_mode: String(process.env.DEMO_MODE ?? 'true').toLowerCase() === 'true',
      provider_configured: Boolean(
        process.env.WORKBUDDY_BASE_URL && process.env.WORKBUDDY_API_KEY && process.env.WORKBUDDY_MODEL
      ),
      database_configured: /^postgres(ql)?:\/\//i.test(String(process.env.DATABASE_URL ?? '')),
    })
  );
});
