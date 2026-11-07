/**
 * Pyzex Guard — Vercel serverless entry point.
 *
 * The Express app is invoked directly as a Node handler. All /api/* traffic
 * is routed here by vercel.json; static dashboard assets are served by the
 * @vercel/static build from /public.
 */
import { createApp } from '../lib/app.js';

const app = createApp();

export default function handler(req, res) {
  return app(req, res);
}
