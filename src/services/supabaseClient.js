import { createClient } from '@supabase/supabase-js';

const rawUrl = import.meta.env.VITE_SUPABASE_URL || '';
const rawKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

// Clean URL: remove quotes, remove /rest/v1 suffix, remove trailing slash
const sanitizeUrl = (url) => {
  if (!url) return '';
  return url
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/\/rest\/v1\/?$/, '')
    .replace(/\/+$/, '');
};

const sanitizeKey = (key) => {
  if (!key) return '';
  return key.trim().replace(/^["']|["']$/g, '');
};

const cleanUrl = sanitizeUrl(rawUrl);
const cleanKey = sanitizeKey(rawKey);

export const isSupabaseConfigured = () => {
  return Boolean(
    cleanUrl &&
    cleanKey &&
    cleanUrl.startsWith('https://') &&
    !cleanUrl.includes('your-project-id')
  );
};

export const supabase = isSupabaseConfigured()
  ? createClient(cleanUrl, cleanKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    })
  : null;
