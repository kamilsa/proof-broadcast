import { defineConfig, type Plugin } from 'vite';
import { closeSync, createReadStream, existsSync, openSync, readSync, readdirSync, statSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(fileURLToPath(new URL('.', import.meta.url)), '..');
const TRACE_SUFFIX = '.netviz.ndjson';

/** Header line of a trace, read without loading the whole file. */
function traceMeta(path: string): Record<string, unknown> {
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(512 * 1024);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const text = buf.subarray(0, n).toString('utf8');
    const line = text.slice(0, text.indexOf('\n') >= 0 ? text.indexOf('\n') : undefined);
    return JSON.parse(line).meta ?? {};
  } catch {
    return {};
  } finally {
    closeSync(fd);
  }
}

// Serves traces found in ../shadow-output* directories so the app can list and open them.
function traces(): Plugin {
  return {
    name: 'proof-broadcast-traces',
    configureServer(server) {
      server.middlewares.use('/api/traces', (_req, res) => {
        const found: Array<{ path: string; label: string; mtime: number }> = [];
        for (const dir of readdirSync(REPO)) {
          if (!dir.startsWith('shadow-output')) continue;
          const full = resolve(REPO, dir);
          if (!statSync(full).isDirectory()) continue;
          for (const file of readdirSync(full)) {
            if (!file.endsWith(TRACE_SUFFIX)) continue;
            const path = resolve(full, file);
            const meta = traceMeta(path);
            const title = String(meta.title || meta.mode || file);
            found.push({ path: `${dir}/${file}`, label: `${title} — ${dir}/${file}`, mtime: statSync(path).mtimeMs });
          }
        }
        found.sort((a, b) => b.mtime - a.mtime);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(found));
      });
      server.middlewares.use('/traces/', (req, res, next) => {
        const rel = decodeURIComponent((req.url ?? '').split('?')[0]).replace(/^\/+/, '');
        const path = resolve(REPO, rel);
        if (!path.startsWith(REPO + sep) || !path.endsWith(TRACE_SUFFIX) || !existsSync(path)) {
          next();
          return;
        }
        res.setHeader('Content-Type', 'application/x-ndjson');
        createReadStream(path).pipe(res);
      });
    },
  };
}

export default defineConfig({
  plugins: [traces()],
  server: { port: 5188 },
});
